// Local AI - PDF text reader. Created by Claude (Anthropic).
//
// Reads ONLY what a person can actually see on each page:
//  * Every page is rendered to an image and read with Apple's on-device text
//    recognition (Vision). That reads scanned pages, and it is the reference
//    for what is visible.
//  * The PDF's own text layer is used line by line, and only where the
//    recognizer saw text in the same spot on the rendered page. A line of the
//    text layer that sits where nothing is visible (white-on-white, tiny,
//    off-page or covered text: the usual way to hide instructions for an AI)
//    is dropped, however short it is. A line where text is visible but most
//    of its words don't match what was seen is dropped too.
//  * Nothing in the PDF is executed: no JavaScript, links, forms, embedded
//    files or launch actions. The server also runs this in a sandbox with no
//    network and no file writes.
//
// Prints one JSON object: {"pages", "read", "ocr", "hidden", "hidden_lines", "unchecked", "unread", "text"}.
// Exit codes: 0 ok, 2 unreadable, 3 password-protected.
//
// `pdftext --rich <file>` reads Word, RTF, OpenDocument and HTML files the
// same careful way: text that's invisible (white or transparent, tiny, or
// the same color as its background) is dropped. Prints {"hidden_runs", "text"}.
// Built by build.sh into the app's Contents/MacOS/pdftext.
import Foundation
import PDFKit
import Vision
import AppKit

let maxPages = 1000                // pages past this are not read
let renderLongSide: CGFloat = 2600 // pixels for the careful text recognition pass
let maxChars = 2_000_000           // stop collecting text past this (the app keeps 2M)

func emit(_ obj: [String: Any]) -> Never {
    guard let data = try? JSONSerialization.data(withJSONObject: obj) else { exit(2) }
    // A full disk, a closed pipe or the server's output cap must end in a clean
    // failure code, not a crash: ignore the signals and check the write.
    signal(SIGPIPE, SIG_IGN)
    signal(SIGXFSZ, SIG_IGN)
    do { try FileHandle.standardOutput.write(contentsOf: data) } catch { exit(4) }
    exit(0)
}

func words(_ s: String, min: Int = 2) -> [String] {
    s.lowercased().split { !$0.isLetter && !$0.isNumber }.map(String.init).filter { $0.count >= min }
}

struct Seen { let text: String; let rect: CGRect }   // one recognized line, in page coordinates

func recognize(_ page: PDFPage, accurate: Bool) -> [Seen]? {
    let box = page.bounds(for: .cropBox)           // the area a PDF viewer actually shows
    guard box.width > 1, box.height > 1, box.width.isFinite, box.height.isFinite else { return nil }
    let rot = ((page.rotation % 360) + 360) % 360  // 0, 90, 180 or 270: how the page is displayed
    let sideways = rot == 90 || rot == 270
    let scale = (accurate ? renderLongSide : 1400) / max(box.width, box.height)
    // The rendered image has the page's display orientation, so a sideways page swaps width and height.
    let size = sideways ? NSSize(width: box.height * scale, height: box.width * scale)
                        : NSSize(width: box.width * scale, height: box.height * scale)
    let thumb = page.thumbnail(of: size, for: .cropBox)       // applies page rotation
    guard let cg = thumb.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return nil }
    let req = VNRecognizeTextRequest()
    req.recognitionLevel = accurate ? .accurate : .fast
    req.usesLanguageCorrection = accurate
    if #available(macOS 13.0, *) { req.automaticallyDetectsLanguage = true }
    do { try VNImageRequestHandler(cgImage: cg, options: [:]).perform([req]) } catch { return nil }
    let obs = (req.results ?? []).sorted {
        // top-to-bottom, then left-to-right (Vision's origin is bottom-left)
        abs($0.boundingBox.midY - $1.boundingBox.midY) > 0.01
            ? $0.boundingBox.midY > $1.boundingBox.midY
            : $0.boundingBox.minX < $1.boundingBox.minX
    }
    return obs.compactMap { o -> Seen? in
        guard let s = o.topCandidates(1).first?.string else { return nil }
        let b = o.boundingBox
        // Vision's box is relative to the rendered (displayed) page. Undo the display
        // rotation so it lands in the same unrotated space as the text layer's boxes.
        func unrotate(_ u: CGFloat, _ v: CGFloat) -> CGPoint {
            switch rot {
            case 90:  return CGPoint(x: 1 - v, y: u)
            case 180: return CGPoint(x: 1 - u, y: 1 - v)
            case 270: return CGPoint(x: v, y: 1 - u)
            default:  return CGPoint(x: u, y: v)
            }
        }
        let p1 = unrotate(b.minX, b.minY), p2 = unrotate(b.maxX, b.maxY)
        let nx = min(p1.x, p2.x), ny = min(p1.y, p2.y), nw = abs(p1.x - p2.x), nh = abs(p1.y - p2.y)
        let r = CGRect(x: box.minX + nx * box.width, y: box.minY + ny * box.height,
                       width: nw * box.width, height: nh * box.height)
        return Seen(text: s, rect: r)
    }
}

// ----------------------------------------------------------------- PDF mode
// One line of the PDF's text layer and where it sits on the page.
struct LayerLine { let text: String; let rect: CGRect? }

func layerLines(_ page: PDFPage) -> [LayerLine] {
    guard let s = page.string, !s.isEmpty else { return [] }
    let ns = s as NSString
    var out: [LayerLine] = []
    var pos = 0
    while pos < ns.length {
        let lineRange = ns.lineRange(for: NSRange(location: pos, length: 0))
        let line = ns.substring(with: lineRange).trimmingCharacters(in: .whitespacesAndNewlines)
        if !line.isEmpty {
            var rect: CGRect? = nil
            var i = lineRange.location
            let end = lineRange.location + lineRange.length
            var n = 0
            while i < end {
                let ch = ns.character(at: i)
                if ch != 32 && ch != 9 && ch != 10 && ch != 13 {
                    let b = page.characterBounds(at: i)
                    if b.width > 0 && b.height > 0 && b.origin.x.isFinite && b.origin.y.isFinite {
                        rect = rect.map { $0.union(b) } ?? b
                    }
                }
                n += 1
                i += n > 60 ? 3 : 1             // long lines: sample every third character
            }
            out.append(LayerLine(text: line, rect: rect))
        }
        if lineRange.length == 0 { break }
        pos = lineRange.location + lineRange.length
    }
    return out
}

// Is this text-layer line visible on the rendered page? It must overlap a
// recognized line, and most of its words must have been seen nearby.
func visible(_ line: LayerLine, seen: [Seen], pageWords: Set<String>) -> Bool {
    let w = words(line.text)
    guard let r = line.rect else {
        // No geometry (unusual): fall back to a page-wide word check.
        if w.isEmpty { return true }
        let unseen = w.filter { !pageWords.contains($0) }.count
        return !(unseen >= 2 && Double(unseen) / Double(w.count) > 0.5)
    }
    let grown = r.insetBy(dx: -r.height, dy: -r.height * 0.6)
    let near = seen.filter { $0.rect.intersects(grown) }
    if near.isEmpty { return false }                        // nothing can be seen where this line is
    if w.count < 2 { return true }                           // one short token: trust the geometry
    if r.height < 7 { return true }                          // fine print: the recognizer misreads it; geometry is enough
    var local = Set<String>()
    for s in near { local.formUnion(words(s.text)) }
    let unseen = w.filter { !local.contains($0) }.count
    return !(unseen >= 2 && Double(unseen) / Double(w.count) > 0.5)
}

// Words of a text-layer line that were not seen anywhere near it: hidden
// words tacked onto the end of a visible line are cut off here.
func trimUnseenTail(_ line: LayerLine, seen: [Seen]) -> String {
    guard let r = line.rect, r.height >= 7 else { return line.text }
    let grown = r.insetBy(dx: -r.height, dy: -r.height * 0.6)
    var local = Set<String>()
    for s in seen where s.rect.intersects(grown) { local.formUnion(words(s.text)) }
    // Walk the line's words from the end; drop a run of >= 3 unseen words at the tail.
    let tokens = line.text.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
    var cut = tokens.count
    var unseenRun = 0
    for (k, t) in tokens.enumerated().reversed() {
        let ws = words(t)
        if ws.isEmpty { continue }
        if ws.allSatisfy({ !local.contains($0) }) { unseenRun += 1; cut = k } else { break }
    }
    if unseenRun >= 3 && cut < tokens.count { return tokens[0..<cut].joined(separator: " ") }
    return line.text
}

// ---------------------------------------------------------------- rich mode
func isInvisible(_ attrs: [NSAttributedString.Key: Any]) -> Bool {
    if let font = attrs[.font] as? NSFont, font.pointSize < 6 { return true }      // too small for a person to read
    func rgb(_ c: NSColor?) -> NSColor? { c?.usingColorSpace(.sRGB) }
    let fg = rgb(attrs[.foregroundColor] as? NSColor) ?? NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 1)
    if fg.alphaComponent < 0.15 { return true }
    // What's behind the text: its own highlight, else the shading of the paragraph,
    // table cell or box it sits in, else a white page.
    var behind = rgb(attrs[.backgroundColor] as? NSColor)
    if behind == nil, let para = attrs[.paragraphStyle] as? NSParagraphStyle {
        for block in para.textBlocks.reversed() {
            if let c = rgb(block.backgroundColor), c.alphaComponent > 0.5 { behind = c; break }
        }
    }
    let bg = behind ?? NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1)
    let d = abs(fg.redComponent - bg.redComponent) + abs(fg.greenComponent - bg.greenComponent) + abs(fg.blueComponent - bg.blueComponent)
    return d < 0.12                                     // text the same color as what's behind it
}

/// Selectors from the page's <style> blocks whose rule hides what it matches
/// (invisible, see-through, tiny, pushed off the page, squeezed or clipped away).
func hidingSelectors(_ html: String) -> [String] {
    func matches(_ pattern: String, _ text: String) -> Bool {
        text.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
    }
    func hides(_ d: String) -> Bool {
        let end = "\\s*(!important\\s*)?(;|$)"
        if matches("visibility\\s*:\\s*(hidden|collapse)", d) { return true }
        if matches("opacity\\s*:\\s*(0|0?\\.0\\d*)" + end, d) { return true }
        if matches("font-size\\s*:\\s*(0(\\.0+)?[a-z%]*|[0-3]?\\.\\d+p[xt]|[1-3](\\.\\d+)?p[xt]|0?\\.(0\\d*|1\\d*|2[0-4]\\d*|2)r?em|(\\d|1\\d|2[0-4])(\\.\\d+)?%)" + end, d) { return true }
        if matches("(^|[;\\s])(left|top|right|bottom|text-indent|margin-left|margin-top)\\s*:\\s*-\\d{3,}", d) { return true }
        if matches("overflow\\s*:\\s*hidden", d) && matches("(^|[;\\s])(max-)?(height|width)\\s*:\\s*[01](px)?" + end, d) { return true }
        if matches("clip\\s*:\\s*rect\\(\\s*[01](px)?[\\s,]", d) || matches("clip-path\\s*:\\s*(inset\\(\\s*(50|100)%|circle\\(\\s*0)", d) { return true }
        if matches("transform\\s*:[^;]*scale[xy]?\\(\\s*0\\s*[,)]", d) { return true }
        if matches("(^|[;\\s])color\\s*:\\s*(transparent|rgba\\([^)]*,\\s*0(\\.0+)?\\s*\\))", d) { return true }
        return false
    }
    var found: [String] = []
    guard let blocks = try? NSRegularExpression(pattern: "<style\\b[^>]*>(.*?)</style\\s*>", options: [.caseInsensitive, .dotMatchesLineSeparators]) else { return [] }
    let ns = html as NSString
    for m in blocks.matches(in: html, range: NSRange(location: 0, length: ns.length)).prefix(50) {
        var css = ns.substring(with: m.range(at: 1))
        if css.utf16.count > 500_000 { css = String(css.prefix(500_000)) }
        css = css.replacingOccurrences(of: "(?s)/\\*.*?\\*/", with: " ", options: .regularExpression)   // comments, also over several lines
        if let open = css.range(of: "/*") { css = String(css[..<open.lowerBound]) }    // an unclosed comment runs to the end, as in a browser
        // One pass: "prelude { declarations }", stepping inside @media and friends.
        var prelude = "", decl = "", inRule = false
        for ch in css {
            if inRule {
                if ch == "}" {
                    if hides(decl) {
                        for sel in prelude.split(separator: ",") {
                            let t = sel.trimmingCharacters(in: .whitespacesAndNewlines)
                            let low = t.lowercased()
                            if t.isEmpty || t.count > 200 || ["html", "body", "*", ":root", "html body"].contains(low) { continue }
                            if t.contains("<") || t.contains("{") || t.contains("}") || t.contains("@") { continue }
                            found.append(t)
                        }
                    }
                    inRule = false; prelude = ""; decl = ""
                } else if ch == "{" {                 // not a plain rule after all: start over from here
                    prelude = ""; decl = ""; inRule = false
                } else { decl.append(ch) }
            } else if ch == "{" {
                if prelude.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("@") { prelude = "" }   // a wrapper: its rules follow
                else { inRule = true; decl = "" }
            } else if ch == "}" || ch == ";" {
                prelude = ""
            } else { prelude.append(ch) }
            if found.count >= 400 { return found }
        }
    }
    return found
}

if CommandLine.arguments.count > 2 && CommandLine.arguments[1] == "--rich" {
    let url = URL(fileURLWithPath: CommandLine.arguments[2])
    let types: [String: NSAttributedString.DocumentType] = [
        "docx": .officeOpenXML, "doc": .docFormat, "rtf": .rtf, "rtfd": .rtfd, "odt": .openDocument,
        "html": .html, "htm": .html, "webarchive": .webArchive, "wordml": .wordML]
    guard let type = types[url.pathExtension.lowercased()] else { exit(2) }
    var opts: [NSAttributedString.DocumentReadingOptionKey: Any] = [.documentType: type]
    if type == .html || type == .webArchive {
        opts[.timeout] = 5                               // and the sandbox blocks any network anyway
        opts[.characterEncoding] = String.Encoding.utf8.rawValue
    }
    var loaded: NSAttributedString?
    if type == .html, var data = try? Data(contentsOf: url) {
        // Web pages hide text in ways that leave no trace on the text itself (invisible,
        // see-through, pushed off the page, squeezed to nothing). Tell the reader to
        // drop those pieces, the same as it already drops display:none.
        let tricks = ["visibility:hidden", "visibility: hidden", "visibility:collapse", "visibility: collapse",
                      "font-size:0", "font-size: 0", "font-size:.", "font-size: .", "font-size:1p", "font-size: 1p", "font-size:2p", "font-size: 2p", "font-size:3p", "font-size: 3p",
                      "left:-", "left: -", "top:-", "top: -", "text-indent:-", "text-indent: -", "margin-left:-9", "margin-left: -9",
                      "height:0", "height: 0", "width:0", "width: 0", "clip:", "clip-path:", "transform:scale(0", "transform: scale(0"]
        var css = tricks.map { "[style*=\"\($0)\" i]" }.joined(separator: ",")
        css += ",[style*=\"opacity:0\" i]:not([style*=\"opacity:0.\" i]),[style*=\"opacity: 0\" i]:not([style*=\"opacity: 0.\" i])"
        css += ",[style*=\"opacity:0.0\" i],[style*=\"opacity: 0.0\" i],[style*=\"opacity:.0\" i],[style*=\"opacity: .0\" i],[hidden],[aria-hidden=\"true\" i]"
        // The same tricks done through the page's own style sheet (a class or id that hides).
        let own = hidingSelectors(String(decoding: data.prefix(4_000_000), as: UTF8.self))
        // One rule per page selector: a selector the reader can't parse voids only its own rule,
        // never the built-in list (an invalid selector in a list throws the whole rule away).
        css += "{display:none !important}"
        for sel in own { css += "\n" + sel + "{display:none !important}" }
        data.append(Data(("<style>" + css + "</style>").utf8))
        loaded = try? NSAttributedString(data: data, options: opts, documentAttributes: nil)
    } else {
        loaded = try? NSAttributedString(url: url, options: opts, documentAttributes: nil)
    }
    guard let a = loaded else { exit(2) }
    var kept = "", hiddenRuns = 0
    a.enumerateAttributes(in: NSRange(location: 0, length: a.length)) { attrs, range, stop in
        let piece = (a.string as NSString).substring(with: range)
        if isInvisible(attrs) && piece.trimmingCharacters(in: .whitespacesAndNewlines).count > 0 {
            hiddenRuns += 1
            kept += piece.filter { $0 == "\n" }             // keep line breaks so paragraphs don't merge
        } else {
            kept += piece
        }
        if kept.utf16.count > maxChars { stop.pointee = true }
    }
    emit(["hidden_runs": hiddenRuns, "text": kept])
}

guard CommandLine.arguments.count > 1 else { exit(2) }
guard let doc = PDFDocument(url: URL(fileURLWithPath: CommandLine.arguments[1])) else { exit(2) }
if doc.isLocked { exit(3) }

var out = ""
var ocrPages: [Int] = [], hiddenPages: [Int] = [], uncheckedPages: [Int] = [], unreadPages: [Int] = []
var hiddenLines = 0
let count = doc.pageCount
let toRead = min(count, maxPages)
var readCount = 0
for i in 0..<toRead {
    if out.utf16.count > maxChars { break }
    readCount = i + 1
    autoreleasepool {
        guard let page = doc.page(at: i) else { unreadPages.append(i + 1); return }
        let lines = layerLines(page)
        var text = ""
        if lines.allSatisfy({ words($0.text, min: 3).isEmpty }) {
            // Scanned page (no usable text layer): read it carefully.
            // (retry once: the first run of the recognizer can fail while it loads its model)
            var seen = recognize(page, accurate: true)
            if seen == nil || seen!.isEmpty { usleep(300_000); seen = recognize(page, accurate: true) }
            if let seen = seen, !seen.isEmpty {
                text = seen.map { $0.text }.joined(separator: "\n"); ocrPages.append(i + 1)
            } else { unreadPages.append(i + 1) }
        } else if let quick = recognize(page, accurate: false) {
            // Check every text-layer line against what the quick reader saw; if any
            // line looks hidden, confirm with the careful reader so ordinary
            // recognition mistakes don't throw away good text.
            func keep(_ seen: [Seen]) -> ([String], Int) {
                var pageWords = Set<String>()
                for s in seen { pageWords.formUnion(words(s.text)) }
                var kept: [String] = [], dropped = 0
                for l in lines {
                    if !visible(l, seen: seen, pageWords: pageWords) { dropped += 1; continue }
                    let t = trimUnseenTail(l, seen: seen)
                    if t.count < l.text.count { dropped += 1 }
                    kept.append(t)
                }
                return (kept, dropped)
            }
            var (kept, dropped) = keep(quick)
            if dropped > 0, let careful = recognize(page, accurate: true), !careful.isEmpty {
                (kept, dropped) = keep(careful)
            }
            if dropped > 0 { hiddenPages.append(i + 1); hiddenLines += dropped }
            text = kept.joined(separator: "\n")
        } else {
            // Couldn't render the page to check it: don't trust its text layer.
            uncheckedPages.append(i + 1)
        }
        if !text.isEmpty { out += "\n--- Page \(i + 1) ---\n" + text + "\n" }
    }
}

// "read" < "pages" means the pages after it were skipped (too many pages or too much text).
emit(["pages": count, "read": readCount, "ocr": ocrPages, "hidden": hiddenPages, "hidden_lines": hiddenLines,
      "unchecked": uncheckedPages, "unread": unreadPages, "text": out])
