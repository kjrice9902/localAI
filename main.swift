// Local AI - native macOS shell.
// Created and maintained by Claude (Anthropic's AI), Nov 2026.
//
// Starts the bundled Ollama + the Python chat server, shows the chat in a
// WKWebView, and gives the app real Edit / View / Window menus
// (copy-paste, Cmd +/-/0 zoom, reload, full screen). Ollama is told to keep
// only ONE model in memory at a time, so switching models never stacks two
// of them in RAM.
//
// The page talks to this shell through window.webkit.messageHandlers.localai
// (dictation with Apple's on-device speech recognition, saving code to a
// file) and gets answers through window.__localaiEvent(...).
//
// Build: ./build.sh (next to this file).

import Cocoa
import WebKit
import Speech
import AVFoundation
import UniformTypeIdentifiers
import PDFKit
import CryptoKit
import LocalAuthentication
import Carbon.HIToolbox

let appName = "Local AI"

extension Data {
    init?(hexString: String) {
        var bytes = [UInt8](), it = hexString.makeIterator()
        while let a = it.next() {
            guard let b = it.next(), let v = UInt8(String([a, b]), radix: 16) else { return nil }
            bytes.append(v)
        }
        self.init(bytes)
    }
}
// A new secret every launch. The chat server only answers requests that carry
// it (as a cookie only this app's web view has), so other programs on the Mac
// can't read or change chats. It also lets the app check that the server on
// port 7861 really is its own before showing it.
// A second per-launch secret, shared only with the server (never with the page). The app
// uses it to sign a command the person approved in the "Run this on your Mac?" window;
// the server runs nothing on the Mac without that signature.
let nativeKey: String = {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return "" }
    return bytes.map { String(format: "%02x", $0) }.joined()
}()

let sessionToken: String = {
    var bytes = [UInt8](repeating: 0, count: 32)
    // No random numbers = no secret: the server then refuses to start open, and the app stops.
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return "" }
    return bytes.map { String(format: "%02x", $0) }.joined()
}()
let supportDir = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/LocalAI")
let legacySupportDir = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/QwenLocal")
let uiPort = 7861
// A private port, so a separately installed Ollama (on 11434) is never adopted.
let ollamaPort = 11435
let ollamaHost = "127.0.0.1:\(ollamaPort)"
let zoomKey = "pageZoom"

// MARK: - Dictation
// Microphone -> Apple's Speech framework (on-device when the Mac supports it)
// -> partial transcripts sent to the page. Stops by itself after ~2 s of
// silence once something has been heard, or when the page says stop.
final class Dictation {
    private let engine = AVAudioEngine()
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var silenceTimer: Timer?
    private var stopTimer: Timer?
    private var lastText = ""
    private var lastChange = Date()
    private var active = false
    private var wanted = false   // false once the page asked to stop, even mid-startup
    private var generation = 0   // bumps per session; callbacks from an older session are ignored
    var onEvent: ([String: Any]) -> Void = { _ in }

    func start() {
        wanted = true
        let rec = SFSpeechRecognizer(locale: Locale.current) ?? SFSpeechRecognizer(locale: Locale(identifier: "en-US"))
        guard let recognizer = rec, recognizer.isAvailable else {
            onEvent(["type": "status", "state": "unavailable",
                     "message": "Speech recognition isn't available on this Mac right now."])
            return
        }
        SFSpeechRecognizer.requestAuthorization { auth in
            DispatchQueue.main.async {
                guard auth == .authorized else {
                    self.onEvent(["type": "status", "state": "denied",
                                  "message": "Speech recognition isn't allowed. Turn it on in System Settings › Privacy & Security › Speech Recognition."])
                    return
                }
                AVCaptureDevice.requestAccess(for: .audio) { ok in
                    DispatchQueue.main.async {
                        guard ok else {
                            self.onEvent(["type": "status", "state": "denied",
                                          "message": "Microphone access isn't allowed. Turn it on in System Settings › Privacy & Security › Microphone."])
                            return
                        }
                        self.begin(recognizer)
                    }
                }
            }
        }
    }

    private func begin(_ recognizer: SFSpeechRecognizer) {
        cleanup()
        generation += 1
        let gen = generation
        guard wanted else { onEvent(["type": "status", "state": "stopped"]); return }
        let req = SFSpeechAudioBufferRecognitionRequest()
        req.shouldReportPartialResults = true
        let onDevice = recognizer.supportsOnDeviceRecognition
        if onDevice { req.requiresOnDeviceRecognition = true }
        request = req

        let input = engine.inputNode
        let fmt = input.outputFormat(forBus: 0)
        guard fmt.sampleRate > 0, fmt.channelCount > 0 else {
            onEvent(["type": "status", "state": "error", "message": "No microphone was found."])
            return
        }
        input.installTap(onBus: 0, bufferSize: 1024, format: fmt) { buffer, _ in req.append(buffer) }
        engine.prepare()
        do { try engine.start() } catch {
            cleanup()
            onEvent(["type": "status", "state": "error", "message": "Couldn't open the microphone: \(error.localizedDescription)"])
            return
        }
        active = true
        lastText = ""
        lastChange = Date()
        onEvent(["type": "status", "state": "listening", "onDevice": onDevice])

        task = recognizer.recognitionTask(with: req) { [weak self] result, error in
            DispatchQueue.main.async {
                guard let self = self, self.active, self.generation == gen else { return }
                if let r = result {
                    let text = r.bestTranscription.formattedString
                    if text != self.lastText { self.lastText = text; self.lastChange = Date() }
                    self.onEvent(["type": r.isFinal ? "final" : "partial", "text": text])
                    if r.isFinal { self.finish(); return }
                }
                if error != nil { self.finish() }
            }
        }
        silenceTimer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            guard let self = self, self.active, self.generation == gen else { return }
            if !self.lastText.isEmpty && Date().timeIntervalSince(self.lastChange) > 2.2 { self.stop() }
        }
    }

    /// Stop recording and let the recognizer deliver its final text.
    func stop() {
        guard active else {
            if wanted { wanted = false; onEvent(["type": "status", "state": "stopped"]) }
            return
        }
        wanted = false
        silenceTimer?.invalidate(); silenceTimer = nil
        engine.inputNode.removeTap(onBus: 0)
        if engine.isRunning { engine.stop() }
        request?.endAudio()
        stopTimer?.invalidate()
        stopTimer = Timer.scheduledTimer(withTimeInterval: 2.5, repeats: false) { [weak self] _ in self?.finish() }
    }

    private func finish() {
        guard active else { return }
        active = false
        wanted = false
        cleanup()
        onEvent(["type": "status", "state": "stopped"])
    }

    private func cleanup() {
        silenceTimer?.invalidate(); silenceTimer = nil
        stopTimer?.invalidate(); stopTimer = nil
        engine.inputNode.removeTap(onBus: 0)
        if engine.isRunning { engine.stop() }
        task?.cancel(); task = nil
        request = nil
    }
}

// MARK: - Read aloud
// Reads replies with the Mac's own voice (System Settings > Accessibility >
// Spoken Content picks which one).
final class Speaker: NSObject, AVSpeechSynthesizerDelegate {
    private let synth = AVSpeechSynthesizer()
    private var ids: [ObjectIdentifier: String] = [:]   // which reply each utterance belongs to
    var onEvent: ([String: Any]) -> Void = { _ in }
    override init() { super.init(); synth.delegate = self }
    func speak(_ text: String, id: String) {
        synth.stopSpeaking(at: .immediate)
        let u = AVSpeechUtterance(string: text)
        u.rate = AVSpeechUtteranceDefaultSpeechRate
        ids[ObjectIdentifier(u)] = id
        synth.speak(u)
    }
    func stop() { synth.stopSpeaking(at: .immediate) }
    private func ended(_ u: AVSpeechUtterance) {
        let id = ids.removeValue(forKey: ObjectIdentifier(u)) ?? ""
        onEvent(["type": "speech", "state": "end", "id": id])
    }
    func speechSynthesizer(_ s: AVSpeechSynthesizer, didStart u: AVSpeechUtterance) {
        onEvent(["type": "speech", "state": "start", "id": ids[ObjectIdentifier(u)] ?? ""])
    }
    func speechSynthesizer(_ s: AVSpeechSynthesizer, didFinish u: AVSpeechUtterance) { ended(u) }
    func speechSynthesizer(_ s: AVSpeechSynthesizer, didCancel u: AVSpeechUtterance) { ended(u) }
}

// MARK: - PDF export
// Lays the chat out in an offscreen web view, moves any block that would be
// cut by a page edge onto the next page, then renders one PDF page at a time
// (WKWebView.createPDF with a page-sized rect) and joins them with PDFKit.
// The page count is fixed up front and capped, so it always finishes.
// (NSPrintOperation on an offscreen web view never stops paginating.)
final class PDFExporter: NSObject, WKNavigationDelegate {
    static let pageW: CGFloat = 612, pageH: CGFloat = 792     // US Letter, in points
    static let maxPages = 400
    private var view: WKWebView?
    private var url: URL?
    private var done: ((Bool, String) -> Void)?

    func export(html: String, to url: URL, completion: @escaping (Bool, String) -> Void) {
        self.url = url
        self.done = completion
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .nonPersistent()
        cfg.defaultWebpagePreferences.allowsContentJavaScript = false   // the chat being printed is text and pictures only
        let v = WKWebView(frame: NSRect(x: 0, y: 0, width: Self.pageW, height: Self.pageH), configuration: cfg)
        v.navigationDelegate = self
        view = v
        v.loadHTMLString(html, baseURL: nil)
        // A load that never finishes (crashed web process, enormous chat) still ends with a message.
        DispatchQueue.main.asyncAfter(deadline: .now() + 180) { [weak self] in
            self?.finish(false, "it took too long (the chat may be too big to export in one go)")
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(false, error.localizedDescription)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        finish(false, "the page renderer crashed")
    }

    private func finish(_ ok: Bool, _ info: String) {
        guard let cb = done else { return }          // report once; later events are ignored
        done = nil
        view?.navigationDelegate = nil
        view = nil
        cb(ok, info)
    }

    // Pushes blocks that straddle a page edge down to the next page.
    private static let paginateJS = """
    (function(){
      var H = \(Int(pageH)), TOP = 40;
      document.body.style.margin = '0';
      document.body.style.padding = TOP + 'px 44px 40px';
      var els = document.querySelectorAll('h1,.sub,.who,.att,p,li,pre,tr,blockquote,.c>div,hr');
      for (var i = 0; i < els.length; i++) {
        var r = els[i].getBoundingClientRect(), top = r.top + window.scrollY, bottom = top + r.height;
        var edge = (Math.floor(top / H) + 1) * H - 36;
        if (bottom > edge && r.height < H - 120) {
          var cur = parseFloat(getComputedStyle(els[i]).marginTop) || 0;
          els[i].style.marginTop = (cur + (edge + 36 + TOP) - top) + 'px';
        }
      }
      return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
    })();
    """

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        webView.evaluateJavaScript(Self.paginateJS) { result, _ in
            let height = CGFloat((result as? NSNumber)?.doubleValue ?? Double(Self.pageH))
            let pages = max(1, min(Self.maxPages, Int(ceil(height / Self.pageH))))
            webView.frame = NSRect(x: 0, y: 0, width: Self.pageW, height: CGFloat(pages) * Self.pageH)
            let out = PDFDocument()
            func render(_ i: Int) {
                guard self.done != nil else { return }                      // timed out or failed already
                guard let url = self.url else { return self.finish(false, "no destination") }
                if i >= pages {
                    let ok = out.pageCount > 0 && out.write(to: url)
                    return self.finish(ok, ok ? url.path : "couldn't write the file")
                }
                let cfg = WKPDFConfiguration()
                cfg.rect = CGRect(x: 0, y: CGFloat(i) * Self.pageH, width: Self.pageW, height: Self.pageH)
                webView.createPDF(configuration: cfg) { r in
                    if case .success(let data) = r, let doc = PDFDocument(data: data), let page = doc.page(at: 0) {
                        out.insert(page, at: out.pageCount)
                    }
                    render(i + 1)
                }
            }
            render(0)
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(false, error.localizedDescription)
    }

    // The export page may only be the chat itself: no links, redirects or other pages.
    private var firstLoad = true
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if firstLoad && action.targetFrame?.isMainFrame == true && action.request.url?.absoluteString == "about:blank" {
            firstLoad = false
            return decisionHandler(.allow)
        }
        decisionHandler(.cancel)
    }
}

// MARK: - Web view with a right-click menu the app controls
// WebKit's own "Download Image" starts a download the app never hears about,
// so nothing happens. The picture items are pointed at the app's own save instead.
// The small "quick ask" box. It takes typing without bringing the whole app forward,
// and goes away when you press Esc or click somewhere else.
final class QuickPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override func cancelOperation(_ sender: Any?) { orderOut(nil) }
    override func resignKey() { super.resignKey(); orderOut(nil) }
}

final class AppWebView: WKWebView {
    var onMenu: ((NSMenu) -> Void)?
    override func willOpenMenu(_ menu: NSMenu, with event: NSEvent) {
        super.willOpenMenu(menu, with: event)
        onMenu?(menu)
    }
}

// MARK: - App
final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    var window: NSWindow!
    var webView: WKWebView!
    var children: [Process] = []
    var loaded = false
    let dictation = Dictation()
    let speaker = Speaker()
    var pdfExporters: [PDFExporter] = []   // one per export in progress
    // Preview panel (an app the model wrote, running in a sealed frame of the page)
    var previewOpen = false
    var previewTimer: Timer?
    var pingSentAt: Date?                  // a "still alive?" question the page hasn't answered yet
    var hangPatience: TimeInterval = 12
    var hangAlertUp = false
    var dialogsUp = 0                      // alert/confirm/prompt sheets on screen (the page waits on those)
    var frameDialogTimes: [Date] = []

    // MARK: launch
    func applicationDidFinishLaunching(_ note: Notification) {
        migrateSupportDir()
        killLeftoverChildren()
        try? FileManager.default.createDirectory(at: supportDir.appendingPathComponent("models"),
                                                 withIntermediateDirectories: true)
        buildMenus()
        buildWindow()
        dictation.onEvent = { [weak self] ev in self?.emit(ev) }
        speaker.onEvent = { [weak self] ev in DispatchQueue.main.async { self?.emit(ev) } }
        startOllama()
        startServer()
        waitForServer(attempt: 0)
        NSApp.activate(ignoringOtherApps: true)
        if quickAskEnabled() { setQuickAsk(true) }
    }

    // MARK: quick ask (Control-Option-A from any app, while Local AI is open)
    var hotKeyRef: EventHotKeyRef?
    var hotKeyHandler: EventHandlerRef?
    var quickPanel: QuickPanel?
    var quickField: NSTextField?

    func quickAskEnabled() -> Bool {
        let file = supportDir.appendingPathComponent("settings.json")
        guard let data = try? Data(contentsOf: file),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return true }   // first run: on, like the default
        return obj["quick_ask"] as? Bool ?? true
    }

    func setQuickAsk(_ on: Bool) {
        if !on {
            if let ref = hotKeyRef { UnregisterEventHotKey(ref); hotKeyRef = nil }
            quickPanel?.orderOut(nil)
            return
        }
        guard hotKeyRef == nil else { return }
        if hotKeyHandler == nil {
            var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
                DispatchQueue.main.async { (NSApp.delegate as? AppDelegate)?.toggleQuickAsk() }
                return noErr
            }, 1, &spec, nil, &hotKeyHandler)
        }
        // If another app already owns this shortcut, macOS says no and nothing happens: the app works as before.
        let id = EventHotKeyID(signature: OSType(0x4C414951), id: 1)       // "LAIQ"
        RegisterEventHotKey(UInt32(kVK_ANSI_A), UInt32(controlKey | optionKey), id, GetApplicationEventTarget(), 0, &hotKeyRef)
    }

    func toggleQuickAsk() {
        if let p = quickPanel, p.isVisible { p.orderOut(nil); return }
        // Locked, still starting, or showing an error: just bring the app forward.
        guard loaded, lockView == nil, !blocked else {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        if quickPanel == nil {
            let p = QuickPanel(contentRect: NSRect(x: 0, y: 0, width: 620, height: 58),
                               styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel], backing: .buffered, defer: false)
            p.titleVisibility = .hidden
            p.titlebarAppearsTransparent = true
            p.isMovableByWindowBackground = true
            p.level = .floating
            p.isFloatingPanel = true
            p.hidesOnDeactivate = false
            p.isReleasedWhenClosed = false
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            p.standardWindowButton(.closeButton)?.isHidden = true
            p.standardWindowButton(.miniaturizeButton)?.isHidden = true
            p.standardWindowButton(.zoomButton)?.isHidden = true
            let f = NSTextField(frame: NSRect(x: 16, y: 13, width: 588, height: 30))
            f.placeholderString = "Ask Local AI…   Return sends it, Esc closes"
            f.font = .systemFont(ofSize: 19)
            f.isBordered = false
            f.drawsBackground = false
            f.focusRingType = .none
            f.usesSingleLineMode = true
            f.cell?.isScrollable = true
            f.target = self
            f.action = #selector(quickAskSubmit(_:))
            f.autoresizingMask = [.width]
            p.contentView?.addSubview(f)
            quickPanel = p
            quickField = f
        }
        guard let p = quickPanel, let f = quickField else { return }
        f.stringValue = ""
        let screen = NSScreen.screens.first(where: { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) }) ?? NSScreen.main
        if let vf = screen?.visibleFrame {
            p.setFrameOrigin(NSPoint(x: vf.midX - p.frame.width / 2, y: vf.minY + vf.height * 0.68))
        }
        p.makeKeyAndOrderFront(nil)
        p.makeFirstResponder(f)
    }

    @objc func quickAskSubmit(_ sender: Any?) {
        let text = String((quickField?.stringValue ?? "").trimmingCharacters(in: .whitespacesAndNewlines).prefix(20000))
        quickPanel?.orderOut(nil)
        guard !text.isEmpty, loaded, lockView == nil, !blocked else { return }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        emit(["type": "quickAsk", "text": text])
    }

    // The folder for automatic backups: picked here, in a real folder panel, never typed by the page.
    func pickBackupFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Use This Folder"
        panel.message = "Pick the folder where Local AI puts its automatic backups"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            self.emit(["type": "folder", "path": url.path])
        }
    }

    // The app used to be called Qwen Local; carry its models, settings and
    // threads over the first time this version runs.
    func migrateSupportDir() {
        let fm = FileManager.default
        if !fm.fileExists(atPath: supportDir.path) && fm.fileExists(atPath: legacySupportDir.path) {
            try? fm.moveItem(at: legacySupportDir, to: supportDir)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    // Give the page a moment to save any pending settings before quitting.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard loaded else { return .terminateNow }
        var replied = false
        let finish = { if !replied { replied = true; NSApp.reply(toApplicationShouldTerminate: true) } }
        webView.callAsyncJavaScript("return window.__localaiFlush ? await window.__localaiFlush() : true;",
                                    arguments: [:], in: nil, in: .page) { _ in finish() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { finish() }
        return .terminateLater
    }

    func applicationWillTerminate(_ note: Notification) {
        quitting = true
        for p in children where p.isRunning { p.terminate() }
        let deadline = Date().addingTimeInterval(3)
        while children.contains(where: { $0.isRunning }) && Date() < deadline {
            usleep(50_000)
        }
        for p in children where p.isRunning { kill(p.processIdentifier, SIGKILL) }
    }

    // MARK: child processes
    func baseEnv() -> [String: String] {
        // Only what the children need; nothing else from the launching environment leaks through.
        let parent = ProcessInfo.processInfo.environment
        var env: [String: String] = [:]
        for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SHELL", "__CF_USER_TEXT_ENCODING"] {
            if let v = parent[key] { env[key] = v }
        }
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"   // fixed: never the launcher's, so no look-alike tool can be swapped in
        env["OLLAMA_MODELS"] = supportDir.appendingPathComponent("models").path
        env["OLLAMA_HOST"] = ollamaHost
        env["OLLAMA_KEEP_ALIVE"] = "30m"
        env["OLLAMA_MAX_LOADED_MODELS"] = "1"   // one model in RAM at a time
        env["OLLAMA_NUM_PARALLEL"] = "1"        // one request at a time, smaller cache
        env["OLLAMA_FLASH_ATTENTION"] = "1"
        env["OLLAMA_KV_CACHE_TYPE"] = "q8_0"    // halves memory for long contexts
        env["LOCALAI_OLLAMA_URL"] = "http://" + ollamaHost
        env["LOCALAI_PORT"] = String(uiPort)
        env["LOCALAI_SUPPORT_DIR"] = supportDir.path
        return env
    }

    var pidFile: URL { supportDir.appendingPathComponent("children.pids") }

    /// When a process started, in microseconds. PID + start time names one
    /// process for good: macOS reuses PIDs, but never with the same start time.
    func startTime(_ pid: pid_t) -> UInt64? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
    }

    func savePids() {
        children.removeAll { !$0.isRunning }
        let text = children.compactMap { p -> String? in
            guard p.isRunning, let t = startTime(p.processIdentifier) else { return nil }
            return "\(p.processIdentifier) \(t)"
        }.joined(separator: "\n")
        try? text.write(to: pidFile, atomically: true, encoding: .utf8)
    }

    /// After a crash or Force Quit, the bundled Ollama (with a model in RAM)
    /// and the Python server can be left running. Stop them before starting
    /// fresh ones, but only a process whose PID AND start time match what was
    /// recorded, so an unrelated program that got a reused PID is never touched.
    func killLeftoverChildren() {
        guard let text = try? String(contentsOf: pidFile, encoding: .utf8) else { return }
        var killed: [pid_t] = []
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ")
            guard parts.count == 2, let pid = pid_t(parts[0]), pid > 1, let saved = UInt64(parts[1]),
                  let now = startTime(pid), now == saved else { continue }
            kill(pid, SIGTERM); killed.append(pid)
        }
        let deadline = Date().addingTimeInterval(3)
        while killed.contains(where: { kill($0, 0) == 0 }) && Date() < deadline { usleep(100_000) }
        for pid in killed where kill(pid, 0) == 0 { kill(pid, SIGKILL) }
        try? FileManager.default.removeItem(at: pidFile)
    }

    @discardableResult
    func launch(_ path: String, _ args: [String], logName: String, extraEnv: [String: String], stdinText: String? = nil) -> Process? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.environment = baseEnv().merging(extraEnv) { _, new in new }
        p.currentDirectoryURL = supportDir
        // Fresh log each launch; the last run's log is kept next to it as *.prev.log.
        let log = supportDir.appendingPathComponent(logName)
        let prev = supportDir.appendingPathComponent(logName.replacingOccurrences(of: ".log", with: ".prev.log"))
        try? FileManager.default.removeItem(at: prev)
        try? FileManager.default.moveItem(at: log, to: prev)
        FileManager.default.createFile(atPath: log.path, contents: nil)
        if let h = try? FileHandle(forWritingTo: log) {
            h.truncateFile(atOffset: 0)
            p.standardOutput = h
            p.standardError = h
        }
        defer { try? (p.standardOutput as? FileHandle)?.close() }   // the child keeps its own copy
        let pipe = stdinText == nil ? nil : Pipe()
        if let pipe = pipe { p.standardInput = pipe }
        do {
            try p.run(); children.append(p); savePids()
            if let pipe = pipe, let text = stdinText {
                try? pipe.fileHandleForWriting.write(contentsOf: Data(text.utf8))
                try? pipe.fileHandleForWriting.close()
            }
            return p
        }
        catch { NSLog("LocalAI: failed to start \(path): \(error)"); return nil }
    }

    func portOpen(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        // Non-blocking with a 1-second limit: a firewall that silently drops loopback
        // connections must not freeze the window for a minute.
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if r == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, 1000) == 1 else { return false }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 else { return false }
        return err == 0
    }

    // Leftovers of our own were stopped by killLeftoverChildren(), so anything
    // still on our ports is some other program. Never use it: it could read
    // every prompt (Ollama port) or pose as the app's page (chat port).
    var ollamaProc: Process?, serverProc: Process?
    var blocked = false

    func portTaken(_ port: Int, _ what: String) -> Bool {
        guard portOpen(port) else { return false }
        blocked = true
        showError("Another program is using port \(port), which Local AI needs for \(what).\n" +
                  "Local AI won't connect to it, for your privacy.\n\nQuit that program (or restart the Mac), then open Local AI again.")
        return true
    }

    // The chat server stopped. Its port is free for a moment; if some other
    // program grabs it, the page must never talk to that program (it would get
    // the session cookie and could pose as the app). Restart ours, or stop.
    var serverRestarts: [Date] = []
    func serverEnded() {
        if quitting || blocked { return }
        serverProc = nil
        if portOpen(uiPort) {
            blocked = true
            ollamaProc?.terminate()
            return showError("The chat server stopped and another program took its port (\(uiPort)).\n" +
                             "Local AI stopped so nothing is sent to it.\n\nQuit that program, then open Local AI again.")
        }
        // At most 3 restarts in any hour. (A per-crash countdown let a server that
        // died every 5-9 minutes restart forever.)
        let now = Date()
        serverRestarts = serverRestarts.filter { now.timeIntervalSince($0) < 3600 }
        if serverRestarts.count >= 3 {
            blocked = true
            ollamaProc?.terminate()
            return showError("The chat server keeps stopping.\nCheck \(supportDir.path)/server.log")
        }
        serverRestarts.append(now)
        loaded = false
        startServer()
        waitForServer(attempt: 0)
    }

    func startOllama() {
        if portTaken(ollamaPort, "its models") { return }
        let bundled = Bundle.main.resourceURL!.appendingPathComponent("bin/ollama").path
        let candidates = [bundled]          // only the copy inside the app, never one found elsewhere on the Mac
        guard let bin = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            NSLog("LocalAI: no ollama binary found"); return
        }
        ollamaProc = launch(bin, ["serve"], logName: "ollama.log", extraEnv: [:])
        ollamaProc?.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.ollamaEnded() }
        }
    }

    // If the model server stops while the app is open, its port is free for a
    // moment. Restart ours right away; if some other program already grabbed
    // the port, stop the chat server so no prompt is ever sent to it.
    var quitting = false
    var ollamaRestarts: [Date] = []
    func ollamaEnded() {
        if quitting || blocked { return }
        if portOpen(ollamaPort) {
            blocked = true
            serverProc?.terminate()
            return showError("The model server stopped and another program took its port (\(ollamaPort)).\n" +
                             "Local AI stopped so your chats aren't sent to it.\n\nQuit that program, then open Local AI again.")
        }
        // At most 3 restarts in any hour. (A per-crash countdown let a server that
        // died every 5-9 minutes restart forever.)
        let now = Date()
        ollamaRestarts = ollamaRestarts.filter { now.timeIntervalSince($0) < 3600 }
        if ollamaRestarts.count >= 3 {
            blocked = true
            serverProc?.terminate()
            return showError("The model server keeps stopping.\nCheck \(supportDir.path)/ollama.log")
        }
        ollamaRestarts.append(now)
        startOllama()
    }

    func startServer() {
        if blocked || portTaken(uiPort, "the chat window") { return }
        let script = Bundle.main.resourceURL!.appendingPathComponent("server.py").path
        guard FileManager.default.fileExists(atPath: script) else {
            NSLog("LocalAI: server.py missing"); return
        }
        // -I: ignore PYTHON* variables and user site-packages, so nothing outside the app runs.
        if sessionToken.isEmpty { return showError("Couldn't make a secure key for this launch. Restart your Mac and try again.") }
        serverProc = launch("/usr/bin/python3", ["-I", "-u", script], logName: "server.log",
                            extraEnv: ["LOCALAI_SECRETS": "stdin"],
                            stdinText: "{\"token\": \"\(sessionToken)\", \"native\": \"\(nativeKey)\"}\n")
        serverProc?.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.serverEnded() }
        }
    }

    /// Asks the server on 7861 to prove it knows this launch's secret, without
    /// sending the secret: it must answer HMAC(secret, random challenge).
    func checkServer(_ done: @escaping (Bool) -> Void) {
        let nonce = UUID().uuidString
        let url = URL(string: "http://127.0.0.1:\(uiPort)/api/hello?n=\(nonce)")!
        var req = URLRequest(url: url)
        req.timeoutInterval = 2
        localSession.dataTask(with: req) { data, _, _ in
            let got = (try? JSONSerialization.jsonObject(with: data ?? Data())) as? [String: Any]
            let ok = Self.proofMatches(got?["proof"] as? String, nonce: nonce)
            DispatchQueue.main.async { done(ok) }
        }.resume()
    }

    /// One session for all loopback calls (proxy-free, nothing cached on disk).
    let localSession: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 600
        return URLSession(configuration: cfg)
    }()

    /// Constant-time check of the server's HMAC proof.
    static func proofMatches(_ hex: String?, nonce: String) -> Bool {
        guard let hex = hex, hex.count == 64, let mac = Data(hexString: hex) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: Data("localai-hello:\(nonce)".utf8),
                                                     using: SymmetricKey(data: Data(sessionToken.utf8)))
    }

    var waitGen = 0
    var contextImageId: String?        // the app picture under the last right-click

    func fixImageMenu(_ menu: NSMenu) {
        for item in menu.items {
            let ident = item.identifier?.rawValue ?? ""
            if ident.contains("DownloadImage") || ident.contains("SaveImage") || item.title.hasPrefix("Download Image") || item.title.hasPrefix("Save Image") {
                item.title = "Save Picture…"
                item.target = self
                item.action = #selector(saveContextImage(_:))
                // (shown whenever WebKit offers it: the page's note about which picture
                // was clicked can arrive just after the menu opens)
            } else if ident.contains("OpenImageInNewWindow") || item.title.hasPrefix("Open Image in New Window") {
                item.isHidden = true      // would open in the browser, which can't see the app's pictures
            }
        }
    }
    @objc func saveContextImage(_ sender: Any?) {
        guard let id = contextImageId else {
            emit(["type": "note", "err": true, "message": "Only the app's own pictures can be saved here."])
            return
        }
        saveImage(id: id)
    }
    var downloadDest: [ObjectIdentifier: (URL, URL)] = [:]   // right-click downloads: (temporary file, chosen file)
    var downloadsCancelled = Set<ObjectIdentifier>()
    func waitForServer(attempt: Int) {
        waitGen += 1
        waitLoop(attempt: attempt, gen: waitGen)
    }

    func waitLoop(attempt: Int, gen: Int) {
        if blocked || gen != waitGen { return }           // a newer loop took over (server restarted)
        let retry = {
            if attempt > 150 { // ~30 s
                self.showError("The chat server didn't start.\nCheck \(supportDir.path)/server.log")
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { self.waitLoop(attempt: attempt + 1, gen: gen) }
        }
        if let s = serverProc, !s.isRunning {
            return showError("The chat server stopped while starting.\nCheck \(supportDir.path)/server.log")
        }
        guard portOpen(uiPort) else { return retry() }
        checkServer { ok in
            guard gen == self.waitGen else { return }
            guard ok else { return retry() }
            if let o = self.ollamaProc, !o.isRunning {
                return self.showError("The model server stopped while starting.\nCheck \(supportDir.path)/ollama.log")
            }
            self.unlockThenLoad()
        }
    }

    func loadPage() {
        guard !blocked else { return }
        guard let cookie = HTTPCookie(properties: [
            .domain: "127.0.0.1", .path: "/", .name: "localai", .value: sessionToken,
            HTTPCookiePropertyKey("HttpOnly"): "TRUE", .sameSitePolicy: "Strict",
        ]) else { return showError("Couldn't set up the session.") }
        webView.configuration.websiteDataStore.httpCookieStore.setCookie(cookie) {
            self.webView.load(URLRequest(url: URL(string: "http://127.0.0.1:\(uiPort)/")!))
        }
    }

    // MARK: Touch ID lock (Settings > Privacy > Lock when the app opens)
    // The chat page isn't loaded at all until you unlock, so nothing of your
    // chats is on screen or in memory before that.
    var lockView: NSView?
    var lockLabel: NSTextField?

    func lockEnabled() -> Bool {
        let file = supportDir.appendingPathComponent("settings.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return false }   // first run: nothing to protect yet
        guard let data = try? Data(contentsOf: file),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return true }  // unreadable: lock, don't guess
        return obj["lock_on_open"] as? Bool == true
    }

    var authInFlight = false
    var unlockedOnce = false        // unlocked once this launch: a silent server restart doesn't ask again

    func unlockThenLoad() {
        guard lockEnabled(), !unlockedOnce else { return loadPage() }
        let v = NSView()
        v.wantsLayer = true
        v.layer?.backgroundColor = NSColor(calibratedWhite: 0.04, alpha: 1).cgColor
        let title = NSTextField(labelWithString: "Local AI is locked")
        title.font = .systemFont(ofSize: 22, weight: .semibold)
        title.textColor = .white
        let note = NSTextField(labelWithString: "Unlock with Touch ID or your Mac password to see your chats.")
        note.textColor = NSColor(calibratedWhite: 0.65, alpha: 1)
        let button = NSButton(title: "Unlock", target: self, action: #selector(unlockPressed(_:)))
        button.bezelStyle = .rounded
        button.keyEquivalent = "\r"
        let stack = NSStackView(views: [title, note, button])
        stack.orientation = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        v.addSubview(stack)
        NSLayoutConstraint.activate([stack.centerXAnchor.constraint(equalTo: v.centerXAnchor),
                                     stack.centerYAnchor.constraint(equalTo: v.centerYAnchor)])
        lockView = v
        lockLabel = note
        window.contentView = v
        authenticate()
    }

    @objc func unlockPressed(_ s: Any?) { authenticate() }

    func authenticate() {
        guard !authInFlight else { return }
        authInFlight = true
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            if err?.code == LAError.passcodeNotSet.rawValue {
                // No password at all on this Mac: the lock can't work, so don't trap the user.
                lockLabel?.stringValue = "This Mac has no password or Touch ID set up, so the lock is off."
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.authInFlight = false; self.finishUnlock() }
            } else {
                // Any other problem: stay locked (fail closed) and let the user try again.
                authInFlight = false
                lockLabel?.stringValue = "Couldn't start Touch ID or the password check (\(err?.localizedDescription ?? "unknown error")). Click Unlock to try again."
            }
            return
        }
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "open your chats") { ok, _ in
            DispatchQueue.main.async {
                self.authInFlight = false
                if ok { self.finishUnlock() }
                else { self.lockLabel?.stringValue = "Not unlocked. Click Unlock to try again." }
            }
        }
    }

    func finishUnlock() {
        guard lockView != nil else { return }
        lockView = nil
        unlockedOnce = true
        window.contentView = webView
        if blocked { return }                   // the error page is already loaded in the web view
        loadPage()
    }

    func showError(_ text: String) {
        let safe = text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        let html = "<body style='background:#0a0a12;color:#eee;font:15px -apple-system;display:grid;place-items:center;height:90vh;text-align:center;white-space:pre-wrap'>\(safe)</body>"
        webView.loadHTMLString(html, baseURL: nil)
    }

    // MARK: window
    func buildWindow() {
        let cfg = WKWebViewConfiguration()
        // Nothing the page stores (including the session cookie) is written to disk.
        cfg.websiteDataStore = .nonPersistent()
        cfg.userContentController.add(self, name: "localai")
        let wv = AppWebView(frame: .zero, configuration: cfg)
        wv.onMenu = { [weak self] menu in self?.fixImageMenu(menu) }
        webView = wv
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.setValue(false, forKey: "drawsBackground")
        var z = UserDefaults.standard.double(forKey: zoomKey)
        if z <= 0, let old = UserDefaults(suiteName: "local.qwen.chat")?.double(forKey: zoomKey), old > 0 {
            z = old   // zoom level saved by the old Qwen Local version
            UserDefaults.standard.set(old, forKey: zoomKey)
        }
        webView.pageZoom = z > 0 ? CGFloat(z) : 1.0

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 800),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        // Solid black, draggable title bar above the chat (not overlapping it).
        window.isReleasedWhenClosed = false     // the app keeps it; closing must not free it twice
        window.title = appName
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.appearance = NSAppearance(named: .darkAqua)
        window.backgroundColor = .black
        window.isMovableByWindowBackground = false
        window.minSize = NSSize(width: 520, height: 420)
        window.contentView = webView
        window.center()
        let frameKey = "NSWindow Frame LocalAIMain"
        if UserDefaults.standard.string(forKey: frameKey) == nil,
           let f = UserDefaults(suiteName: "local.qwen.chat")?.string(forKey: "NSWindow Frame QwenLocalMain") {
            UserDefaults.standard.set(f, forKey: frameKey)   // keep the old window size and spot
        }
        window.setFrameAutosaveName("LocalAIMain")
        window.makeKeyAndOrderFront(nil)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if webView.url?.host == "127.0.0.1" { loaded = true }
        setPreviewOpen(false)          // a freshly loaded page has no preview open
    }

    // Open real web links in the default browser, keep the app on localhost.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else { return decisionHandler(.cancel) }
        let scheme = url.scheme?.lowercased() ?? ""
        let isApp = scheme == "http" && url.host == "127.0.0.1" && url.port == uiPort
        // Right-click > Download Image / Save Image As: only the app's own pictures,
        // saved where the user picks in a save panel (see WKDownloadDelegate below).
        if action.shouldPerformDownload {
            return decisionHandler(isApp && url.path.hasPrefix("/api/image/") ? .download : .cancel)
        }
        // The preview frame may only load preview pages from this app's own server.
        // Links, redirects and scripts inside it never open the browser or leave the Mac.
        if action.targetFrame?.isMainFrame == false || !fromMainFrame(action) {
            let ok = (isApp && url.path.hasPrefix("/api/preview/")) || url.absoluteString == "about:blank"
            return decisionHandler(ok ? .allow : .cancel)
        }
        if (isApp && (url.path == "/" || url.path == "/index.html")) || url.absoluteString == "about:blank" || (scheme == "blob" && url.absoluteString.hasPrefix("blob:http://127.0.0.1:\(uiPort)/")) {
            return decisionHandler(.allow)
        }
        // Nothing else is followed, and nothing is handed to the browser: the page has no
        // real links (a click copies the address), so a request to open one isn't the person's.
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        return nil                      // no new windows, and nothing is sent to the browser
    }

    // (sourceFrame is declared non-optional but WebKit can hand over nil; read it safely.)
    func fromMainFrame(_ action: WKNavigationAction) -> Bool {
        (action.value(forKey: "sourceFrame") as? WKFrameInfo)?.isMainFrame ?? true
    }

    // MARK: preview panel
    // alert(), confirm() and prompt() from an app in the preview. A frame that keeps
    // opening them (more than 3 in 10 seconds) gets them answered "no" unseen.
    func frameDialogAllowed(_ frame: WKFrameInfo) -> Bool {
        if frame.isMainFrame { return true }
        let now = Date()
        frameDialogTimes = frameDialogTimes.filter { now.timeIntervalSince($0) < 10 }
        if frameDialogTimes.count >= 3 { return false }
        frameDialogTimes.append(now)
        return true
    }

    func showDialog(_ text: String, cancel: Bool, field: NSTextField?, fromPreview: Bool = false, done: @escaping (Bool) -> Void) {
        let a = NSAlert()
        a.messageText = fromPreview ? "The previewed app (written by the AI) says" : "The app says"
        a.informativeText = String(text.prefix(2000)) + (fromPreview && field != nil ? "\n\n(Never type a password here. What you type goes to the previewed app.)" : "")
        a.addButton(withTitle: "OK")
        if cancel { a.addButton(withTitle: "Cancel") }
        if let field = field { a.accessoryView = field; a.window.initialFirstResponder = field }
        dialogsUp += 1
        let finish: (NSApplication.ModalResponse) -> Void = { r in
            self.dialogsUp -= 1
            self.pingSentAt = nil
            done(r == .alertFirstButtonReturn)
        }
        if let w = window, w.isVisible { a.beginSheetModal(for: w, completionHandler: finish) } else { finish(a.runModal()) }
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        guard frameDialogAllowed(frame) else { return completionHandler() }
        showDialog(message, cancel: false, field: nil, fromPreview: !frame.isMainFrame) { _ in completionHandler() }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard frameDialogAllowed(frame) else { return completionHandler(false) }
        showDialog(message, cancel: true, field: nil, fromPreview: !frame.isMainFrame, done: completionHandler)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
        guard frameDialogAllowed(frame) else { return completionHandler(nil) }
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.stringValue = String((defaultText ?? "").prefix(2000))
        showDialog(prompt, cancel: true, field: field, fromPreview: !frame.isMainFrame) { ok in completionHandler(ok ? field.stringValue : nil) }
    }

    // The preview shares the page's engine, so an app stuck in an endless loop
    // freezes the whole window. While a preview is open the page is asked "still
    // there?" every few seconds; if it stops answering, offer to restart.
    func setPreviewOpen(_ open: Bool) {
        previewOpen = open
        pingSentAt = nil
        hangPatience = 12
        previewTimer?.invalidate()
        previewTimer = nil
        guard open else { return }
        previewTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.checkPreview() }
    }

    func checkPreview() {
        guard previewOpen, loaded, dialogsUp == 0, !hangAlertUp else { return }
        if let sent = pingSentAt {
            let late = Date().timeIntervalSince(sent)
            // (a gap far longer than the timer means the Mac slept, not that the page hung)
            if late > hangPatience + 30 { pingSentAt = Date(); return }
            if late > hangPatience { previewHung() }
            return
        }
        pingSentAt = Date()
        webView.evaluateJavaScript("1") { [weak self] _, _ in self?.pingSentAt = nil }
    }

    func previewHung() {
        hangAlertUp = true
        let a = NSAlert()
        a.messageText = "The app in the preview stopped responding"
        a.informativeText = "It is probably stuck in an endless loop, and that freezes this window. Restart Local AI to get going again. Your chats are saved."
        a.addButton(withTitle: "Restart Local AI")
        a.addButton(withTitle: "Keep Waiting")
        let r = a.runModal()
        hangAlertUp = false
        if r == .alertFirstButtonReturn { restartApp(); return }
        hangPatience = 60
        pingSentAt = pingSentAt == nil ? nil : Date()
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) { webView.reload() }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }
    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    // File chooser for <input type="file"> (the audio upload button).
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        // The app's own page gets a normal picker. A preview app (model-written, runs in a
        // sandboxed frame) gets one that says plainly who is asking. Anything else: no picker.
        let fromApp = frame.isMainFrame && isAppOrigin(frame.securityOrigin)
        let fromPreview = !frame.isMainFrame && webView === self.webView &&
            (frame.request.url.map { $0.scheme == "http" && $0.host == "127.0.0.1" && $0.port == uiPort && $0.path.hasPrefix("/api/preview/") } ?? false)
        guard fromApp || fromPreview else { completionHandler(nil); return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = fromApp && parameters.allowsMultipleSelection
        panel.title = fromApp ? "Choose files" : "The app preview wants a file"
        if !fromApp {
            panel.message = "The app in the preview (written by the AI) is asking for a file. It will be able to read whatever you pick. Only choose a file you're OK sharing with it."
            panel.prompt = "Give to Preview"
        }
        panel.beginSheetModal(for: window) { response in
            completionHandler(response == .OK ? panel.urls : nil)
        }
    }

    // MARK: page <-> shell bridge
    func isAppOrigin(_ origin: WKSecurityOrigin) -> Bool {
        origin.protocol == "http" && origin.host == "127.0.0.1" && origin.port == uiPort
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        // Only the app's own page (main frame, 127.0.0.1:7861) may use the mic, speech or save panels.
        guard message.frameInfo.isMainFrame, isAppOrigin(message.frameInfo.securityOrigin) else { return }
        guard let body = message.body as? [String: Any], let cmd = body["cmd"] as? String else { return }
        switch cmd {
        case "mic.start": dictation.start()
        case "mic.stop": dictation.stop()
        case "speak":
            speaker.speak(String((body["text"] as? String ?? "").prefix(60000)), id: body["id"] as? String ?? "")
        case "stopSpeak":
            speaker.stop()
        case "backup":
            saveBackup()
        case "pickFolder":
            pickBackupFolder()
        case "quickAsk":
            setQuickAsk(body["on"] as? Bool ?? false)
        case "ctxImage":      // the page says which of its pictures was just right-clicked ("" = none)
            let id = body["id"] as? String ?? ""
            contextImageId = (id.count == 16 && id.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isUppercase })) ? id : nil
        case "saveImage":
            let id = body["id"] as? String ?? ""
            if id.count == 16, id.allSatisfy({ $0.isASCII && $0.isHexDigit && !$0.isUppercase }) { saveImage(id: id) }
        case "restart":
            restartApp()
        case "preview":
            setPreviewOpen(body["open"] as? Bool ?? false)
        case "approveAllow":
            approveAllow(id: body["id"] as? String ?? "", names: body["names"] as? [String] ?? [])
        case "approveRun":
            approveRun(id: body["id"] as? String ?? "", lang: body["lang"] as? String ?? "",
                       code: body["code"] as? String ?? "", net: body["net"] as? Bool ?? false)
        case "exportPDF":
            let rawName = (body["name"] as? String ?? "").split(separator: "/").last.map(String.init) ?? ""
            exportPDF(name: rawName.trimmingCharacters(in: CharacterSet(charactersIn: ". ")).isEmpty ? "Chat.pdf" : String(rawName.prefix(100)),
                      html: body["html"] as? String ?? "")
        case "save":
            // Keep only a plain file name; the person picks the folder in the save panel.
            let raw = (body["name"] as? String ?? "").split(separator: "/").last.map(String.init) ?? ""
            let name = raw.trimmingCharacters(in: CharacterSet(charactersIn: ". ")).isEmpty ? "snippet.txt" : String(raw.prefix(100))
            saveFile(name: name, content: body["content"] as? String ?? "")
        default: break
        }
    }

    // MARK: run on the Mac
    // The page asks to run a command or program the model wrote. Show exactly what would
    // run and let the person decide. "Don't Run" is the default button, so a stray Return
    // key never runs anything. One window at a time; more requests wait their turn.
    var approvalQueue: [(id: String, lang: String, code: String, net: Bool)] = []
    var approvalUp = false

    func approveRun(id: String, lang: String, code: String, net: Bool) {
        let idOK = (16...32).contains(id.count) && id.allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }
        guard idOK, lang == "bash" || lang == "python", !code.isEmpty, code.utf8.count <= 200_000, !nativeKey.isEmpty,
              approvalQueue.count < 20 else {
            if idOK { emit(["type": "runApproval", "id": id, "ok": false]) }
            return
        }
        // The window must show everything that would run. Refuse text with invisible or
        // direction-flipping characters, or with padding that pushes lines out of view.
        let hidden = code.unicodeScalars.contains { u in
            let v = u.value
            return (v < 32 && v != 10 && v != 9) || (v >= 0x7f && v <= 0x9f) || v == 0xad || (v >= 0x200b && v <= 0x200f)
                || (v >= 0x2028 && v <= 0x202e) || (v >= 0x2060 && v <= 0x206f) || v == 0xfeff || (v >= 0xe0000 && v <= 0xe0fff)
        }
        let padded = code.range(of: "\n[ \t]*\n[ \t]*\n[ \t]*\n[ \t]*\n", options: .regularExpression) != nil
            || code.range(of: "[ \t]{200,}", options: .regularExpression) != nil
        if hidden || padded {
            emit(["type": "runApproval", "id": id, "ok": false,
                  "why": hidden ? "That code has invisible characters in it, so it wasn't offered to run. Ask the model to write it again in plain text."
                                : "That code has long runs of blank lines or spaces that could hide part of it, so it wasn't offered to run. Ask the model to tidy it."])
            return
        }
        approvalQueue.append((id, lang, code, net))
        nextApproval()
    }

    // Settings > Mac access: the list of look-only commands that may run without the window above.
    // Changing it is confirmed here, in the app, and signed like a run.
    func approveAllow(id: String, names: [String]) {
        let idOK = (16...32).contains(id.count) && id.allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }
        let clean = Array(Set(names)).sorted()
        let namesOK = clean.count <= 30 && clean.allSatisfy { n in (1...12).contains(n.count) && n.allSatisfy { ($0.isASCII && $0.isLowercase) || $0 == "_" } }
        guard idOK, namesOK, !nativeKey.isEmpty, !approvalUp else {
            if idOK { emit(["type": "allowApproval", "id": id, "ok": false]) }
            return
        }
        approvalUp = true
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = clean.isEmpty ? "Ask before every command?" : "Let these commands run without asking?"
        a.informativeText = clean.isEmpty
            ? "Nothing will run on your Mac without the approval window."
            : "When Mac access is on, the AI model can run these by themselves, without the approval window:\n\n" + clean.joined(separator: ", ")
              + "\n\nWithout asking, they can only look inside the \"Local AI Projects\" folder: they can't change anything, use the internet, or read the rest of your Mac. Anything else still asks."
        a.addButton(withTitle: "Cancel")
        let allow = a.addButton(withTitle: clean.isEmpty ? "Ask Every Time" : "Allow These")
        allow.keyEquivalent = ""
        armLater(allow, in: a)
        dialogsUp += 1
        let finish: (NSApplication.ModalResponse) -> Void = { r in
            self.dialogsUp -= 1
            self.pingSentAt = nil
            self.approvalUp = false
            if r == .alertSecondButtonReturn {
                let msg = Data("localai-allow\n\(id)\n\(clean.joined(separator: ","))".utf8)
                let mac = HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: Data(nativeKey.utf8)))
                self.emit(["type": "allowApproval", "id": id, "ok": true, "sig": mac.map { String(format: "%02x", $0) }.joined()])
            } else {
                self.emit(["type": "allowApproval", "id": id, "ok": false])
            }
            self.nextApproval()
        }
        NSApp.activate(ignoringOtherApps: true)
        if let w = window, w.isVisible { a.beginSheetModal(for: w, completionHandler: finish) } else { finish(a.runModal()) }
    }

    /// The approve button can't be pressed by a stray key or a click already on its way:
    /// it never has keyboard focus and only wakes up a moment after the window appears.
    func armLater(_ button: NSButton, in alert: NSAlert) {
        button.refusesFirstResponder = true
        button.isEnabled = false
        alert.window.initialFirstResponder = alert.buttons.first
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { button.isEnabled = true }
    }

    func nextApproval() {
        guard !approvalUp, !approvalQueue.isEmpty else { return }
        let req = approvalQueue.removeFirst()
        approvalUp = true
        let risky = req.code.range(of: #"\brm\s+-[a-zA-Z]*[rf]|\bsudo\b|\bmkfs|\bdd\s+if=|diskutil\s+(erase|partition|reformat)|>\s*/dev/(disk|rdisk)|chmod\s+-R|chown\s+-R|curl[^|\n]*\|\s*(ba|z)?sh|wget[^|\n]*\|\s*(ba|z)?sh|:\(\)\s*\{|shutil\.rmtree|os\.remove|git\s+(reset\s+--hard|clean\s+-[a-z]*f)|\bkillall\b|launchctl|defaults\s+(write|delete)|\.ssh|[Kk]eychain"#,
                                    options: .regularExpression) != nil
        let a = NSAlert()
        a.alertStyle = risky ? .critical : .warning
        a.messageText = req.lang == "bash" ? "Run this command on your Mac?" : "Run this Python program on your Mac?"
        a.informativeText = "The AI model wrote this. It runs for real on your Mac, starting in the folder \"Local AI Projects\" in your home folder, and it can read, change or delete your files."
            + "\nInternet: " + (req.net ? "ON. It can download and upload." : "off.")
            + (risky ? "\n\nWARNING: this looks like it could delete or change a lot. Read it carefully." : "")
        let lineCount = req.code.split(separator: "\n", omittingEmptySubsequences: false).count
        if lineCount > 12 { a.informativeText += "\n\nThis is \(lineCount) lines long. Scroll to read all of it before you choose." }
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 240))
        scroll.hasVerticalScroller = true
        scroll.scrollerStyle = .legacy               // always-visible scroll bar: more text below is never hidden
        scroll.autohidesScrollers = false
        scroll.borderType = .bezelBorder
        let tv = NSTextView(frame: scroll.bounds)
        tv.isEditable = false
        tv.isSelectable = true
        tv.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        tv.string = req.code
        tv.textContainerInset = NSSize(width: 6, height: 6)
        tv.autoresizingMask = [.width]
        scroll.documentView = tv
        a.accessoryView = scroll
        a.addButton(withTitle: "Don't Run")          // first button = default (Return) and Escape
        let run = a.addButton(withTitle: "Run")
        run.keyEquivalent = ""
        armLater(run, in: a)
        dialogsUp += 1
        let finish: (NSApplication.ModalResponse) -> Void = { r in
            self.dialogsUp -= 1
            self.pingSentAt = nil
            self.approvalUp = false
            if r == .alertSecondButtonReturn {
                let msg = Data("localai-run\n\(req.id)\n\(req.lang)\n\(req.net ? "net" : "nonet")\n".utf8) + Data(req.code.utf8)
                let mac = HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: Data(nativeKey.utf8)))
                self.emit(["type": "runApproval", "id": req.id, "ok": true, "sig": mac.map { String(format: "%02x", $0) }.joined()])
            } else {
                self.emit(["type": "runApproval", "id": req.id, "ok": false])
            }
            self.nextApproval()
        }
        NSApp.activate(ignoringOtherApps: true)
        if let w = window, w.isVisible { a.beginSheetModal(for: w, completionHandler: finish) } else { finish(a.runModal()) }
    }

    func emit(_ event: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: event),
              let json = String(data: data, encoding: .utf8) else { return }
        webView.evaluateJavaScript("window.__localaiEvent && window.__localaiEvent(\(json));", completionHandler: nil)
    }

    func exportPDF(name: String, html: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [.pdf]
        panel.canCreateDirectories = true
        panel.title = "Export chat as PDF"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            let exporter = PDFExporter()
            self.pdfExporters.append(exporter)
            exporter.export(html: html, to: url) { ok, info in
                self.pdfExporters.removeAll { $0 === exporter }
                self.emit(ok ? ["type": "note", "message": "Saved to \(info)"]
                             : ["type": "note", "err": true, "message": "Couldn't make the PDF: \(info)"])
            }
        }
    }

    // Heat meter > Restart app: quit cleanly, then a tiny helper opens the app
    // again once this copy has fully exited.
    func restartApp() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        let me = getpid()
        let hash = lstartHash(me)
        // $0 = bundle path, $1 = our pid, $2 = a hash of our start time (or empty): the helper
        // waits while that pid is alive AND still the same process, then opens the app again.
        p.arguments = ["-c", "while kill -0 \"$1\" 2>/dev/null && { [ -z \"$2\" ] || [ \"$(ps -o lstart= -p \"$1\" | md5)\" = \"$2\" ]; }; do sleep 0.2; done; sleep 0.5; /usr/bin/open \"$0\"",
                       Bundle.main.bundlePath, String(me), hash]
        do { try p.run() } catch {
            // Without the helper the app would just quit and not come back: stay open instead.
            emit(["type": "note", "err": true, "message": "Couldn't restart the app (\(error.localizedDescription)). Quit and open it again yourself."])
            return
        }
        NSApp.terminate(nil)
    }

    func lstartHash(_ pid: pid_t) -> String {
        let t = Process()
        t.executableURL = URL(fileURLWithPath: "/bin/sh")
        t.arguments = ["-c", "ps -o lstart= -p \"$0\" | md5", String(pid)]
        let pipe = Pipe()
        t.standardOutput = pipe
        try? t.run()
        t.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    // Settings > Privacy > Back up: asks the server for the backup zip (with
    // this launch's secret) and saves it where you choose.
    func saveBackup() {
        let panel = NSSavePanel()
        let day = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withFullDate])
        panel.nameFieldStringValue = "Local AI backup \(day).zip"
        panel.allowedContentTypes = [.zip]
        panel.canCreateDirectories = true
        panel.title = "Save a backup of all chats, memories and settings"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let dest = panel.url else { return }
            self.emit(["type": "note", "message": "Making the backup…"])
            var req = URLRequest(url: URL(string: "http://127.0.0.1:\(uiPort)/api/backup")!)
            req.setValue("localai=\(sessionToken)", forHTTPHeaderField: "Cookie")
            self.localSession.downloadTask(with: req) { tmp, resp, error in
                var message = "Couldn't make the backup: \(error?.localizedDescription ?? "the server said no")"
                var ok = false
                if let tmp = tmp, (resp as? HTTPURLResponse)?.statusCode == 200 {
                    do {
                        // Swap in the new file; the old backup is only gone once the new one is in place.
                        if FileManager.default.fileExists(atPath: dest.path) {
                            _ = try FileManager.default.replaceItemAt(dest, withItemAt: tmp)
                        } else {
                            try FileManager.default.moveItem(at: tmp, to: dest)
                        }
                        ok = true
                        message = "Backup saved to \(dest.path)"
                    } catch { message = "Couldn't save the backup: \(error.localizedDescription)" }
                }
                DispatchQueue.main.async { self.emit(ok ? ["type": "note", "message": message] : ["type": "note", "err": true, "message": message]) }
            }.resume()
        }
    }

    // A picture from the picture maker: fetched from the local server (with this
    // launch's secret) and saved where you choose.
    func saveImage(id: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Picture.jpg"
        panel.allowedContentTypes = [.jpeg]
        panel.canCreateDirectories = true
        panel.title = "Save picture"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let dest = panel.url,
                  let url = URL(string: "http://127.0.0.1:\(uiPort)/api/image/\(id)") else { return }
            var req = URLRequest(url: url)
            req.setValue("localai=\(sessionToken)", forHTTPHeaderField: "Cookie")
            self.localSession.dataTask(with: req) { data, resp, error in
                var message = "Couldn't save the picture: \(error?.localizedDescription ?? "it's no longer there")"
                var ok = false
                if let data = data, (resp as? HTTPURLResponse)?.statusCode == 200 {
                    do { try data.write(to: dest, options: .atomic); ok = true; message = "Saved to \(dest.path)" }
                    catch { message = "Couldn't save the picture: \(error.localizedDescription)" }
                }
                DispatchQueue.main.async { self.emit(ok ? ["type": "note", "message": message] : ["type": "note", "err": true, "message": message]) }
            }.resume()
        }
    }

    func saveFile(name: String, content: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        panel.title = "Save code"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                try content.write(to: url, atomically: true, encoding: .utf8)
                self.emit(["type": "note", "message": "Saved to \(url.path)"])
            } catch {
                self.emit(["type": "note", "err": true, "message": "Couldn't save: \(error.localizedDescription)"])
            }
        }
    }

    // MARK: zoom
    func setZoom(_ z: CGFloat) {
        let v = min(3.0, max(0.5, (z * 100).rounded() / 100))
        webView.pageZoom = v
        UserDefaults.standard.set(Double(v), forKey: zoomKey)
    }
    @objc func zoomIn(_ s: Any?) { setZoom(webView.pageZoom + 0.1) }
    @objc func zoomOut(_ s: Any?) { setZoom(webView.pageZoom - 0.1) }
    @objc func zoomReset(_ s: Any?) { setZoom(1.0) }
    // Save any pending settings first (large ones don't fit in the page's own
    // last-second save), then reload.
    @objc func reloadPage(_ s: Any?) {
        guard loaded else { webView.reload(); return }
        var done = false
        let go = { if !done { done = true; self.webView.reload() } }
        webView.callAsyncJavaScript("return window.__localaiFlush ? await window.__localaiFlush() : true;",
                                    arguments: [:], in: nil, in: .page) { _ in go() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { go() }
    }

    @objc func showAbout(_ s: Any?) {
        let text = "Created and maintained by Claude, Anthropic's AI.\n" +
            "Qwen 3.5 weights by Alibaba (Apache 2.0). Gemma 4 weights by Google (Apache 2.0).\n" +
            "Runs entirely on this Mac. Nothing leaves it."
        let credits = NSAttributedString(string: text, attributes: [
            .font: NSFont.systemFont(ofSize: 11.5),
            .foregroundColor: NSColor.secondaryLabelColor,
        ])
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits, .applicationName: appName])
    }

    // MARK: menus
    func item(_ title: String, _ action: Selector?, _ key: String, _ mods: NSEvent.ModifierFlags = .command,
              target: AnyObject? = nil) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: key)
        i.keyEquivalentModifierMask = mods
        if let t = target { i.target = t }
        return i
    }

    func buildMenus() {
        let main = NSMenu()

        let app = NSMenu()
        app.addItem(item("About \(appName)", #selector(showAbout(_:)), "", target: self))
        app.addItem(.separator())
        app.addItem(item("Hide \(appName)", #selector(NSApplication.hide(_:)), "h"))
        app.addItem(item("Hide Others", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option]))
        app.addItem(item("Show All", #selector(NSApplication.unhideAllApplications(_:)), ""))
        app.addItem(.separator())
        app.addItem(item("Quit \(appName)", #selector(NSApplication.terminate(_:)), "q"))

        let edit = NSMenu(title: "Edit")
        edit.addItem(item("Undo", Selector(("undo:")), "z"))
        edit.addItem(item("Redo", Selector(("redo:")), "z", [.command, .shift]))
        edit.addItem(.separator())
        edit.addItem(item("Cut", #selector(NSText.cut(_:)), "x"))
        edit.addItem(item("Copy", #selector(NSText.copy(_:)), "c"))
        edit.addItem(item("Paste", #selector(NSText.paste(_:)), "v"))
        edit.addItem(item("Paste and Match Style", #selector(NSTextView.pasteAsPlainText(_:)), "v", [.command, .option, .shift]))
        edit.addItem(item("Select All", #selector(NSText.selectAll(_:)), "a"))

        let view = NSMenu(title: "View")
        view.addItem(item("Actual Size", #selector(zoomReset(_:)), "0", target: self))
        view.addItem(item("Zoom In", #selector(zoomIn(_:)), "=", target: self))
        let plus = item("Zoom In", #selector(zoomIn(_:)), "+", target: self)
        plus.isHidden = true
        plus.allowsKeyEquivalentWhenHidden = true
        view.addItem(plus)
        view.addItem(item("Zoom Out", #selector(zoomOut(_:)), "-", target: self))
        view.addItem(.separator())
        view.addItem(item("Reload", #selector(reloadPage(_:)), "r", target: self))
        view.addItem(item("Enter Full Screen", #selector(NSWindow.toggleFullScreen(_:)), "f", [.command, .control]))

        let win = NSMenu(title: "Window")
        win.addItem(item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"))
        win.addItem(item("Zoom", #selector(NSWindow.performZoom(_:)), ""))
        win.addItem(item("Close", #selector(NSWindow.performClose(_:)), "w"))

        for (title, menu) in [(appName, app), ("Edit", edit), ("View", view), ("Window", win)] {
            let top = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            top.submenu = menu
            main.addItem(top)
        }
        NSApp.mainMenu = main
        NSApp.windowsMenu = win
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()

// MARK: - downloads (right-click > Download Image / Save Image As)
extension AppDelegate: WKDownloadDelegate {
    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let key = ObjectIdentifier(download)
        guard let u = response.url, u.scheme == "http", u.host == "127.0.0.1", u.port == uiPort,
              u.path.hasPrefix("/api/image/"), (response as? HTTPURLResponse)?.statusCode == 200 else {
            downloadsCancelled.insert(key)
            return completionHandler(nil)
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Picture.jpg"
        panel.allowedContentTypes = [.jpeg]
        panel.canCreateDirectories = true
        panel.title = "Save picture"
        panel.beginSheetModal(for: window) { r in
            guard r == .OK, let dest = panel.url else {
                self.downloadsCancelled.insert(key)
                return completionHandler(nil)
            }
            // Download next to nothing of the user's: a temporary file, moved over the
            // chosen one only once it has fully arrived.
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("LocalAI-" + UUID().uuidString + ".jpg")
            self.downloadDest[key] = (tmp, dest)
            completionHandler(tmp)
        }
    }
    func downloadDidFinish(_ download: WKDownload) {
        guard let (tmp, dest) = downloadDest.removeValue(forKey: ObjectIdentifier(download)) else { return }
        do {
            if FileManager.default.fileExists(atPath: dest.path) {
                _ = try FileManager.default.replaceItemAt(dest, withItemAt: tmp)
            } else {
                try FileManager.default.moveItem(at: tmp, to: dest)
            }
            emit(["type": "note", "message": "Saved to \(dest.path)"])
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            emit(["type": "note", "err": true, "message": "Couldn't save the picture: \(error.localizedDescription)"])
        }
    }
    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        let key = ObjectIdentifier(download)
        if let (tmp, _) = downloadDest.removeValue(forKey: key) { try? FileManager.default.removeItem(at: tmp) }
        if downloadsCancelled.remove(key) != nil { return }        // the user cancelled: nothing to say
        emit(["type": "note", "err": true, "message": "Couldn't save the picture: \(error.localizedDescription)"])
    }
}
