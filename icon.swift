// Local AI app icon generator. Created by Claude (Anthropic).
// Draws the app's glowing gradient orb on a dark rounded square and writes a
// 1024x1024 PNG:   swiftc icon.swift -o icongen && ./icongen icon_1024.png
import AppKit

let px = 1024
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon_1024.png"

func c(_ hex: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(deviceRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                           colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
rep.size = NSSize(width: px, height: px)
NSGraphicsContext.saveGraphicsState()
let gctx = NSGraphicsContext(bitmapImageRep: rep)!
NSGraphicsContext.current = gctx
let cg = gctx.cgContext
cg.clear(CGRect(x: 0, y: 0, width: px, height: px))

// Rounded square on the standard macOS icon grid (824 of 1024, ~22% corners).
let bgRect = NSRect(x: 100, y: 100, width: 824, height: 824)
let bgPath = NSBezierPath(roundedRect: bgRect, xRadius: 184, yRadius: 184)
cg.saveGState()
cg.setShadow(offset: CGSize(width: 0, height: -10), blur: 36,
             color: NSColor.black.withAlphaComponent(0.35).cgColor)
c(0x10101c).setFill(); bgPath.fill()
cg.restoreGState()

cg.saveGState()
bgPath.addClip()
NSGradient(colors: [c(0x1c1c32), c(0x08080f)])!.draw(in: bgRect, angle: -90)
// Soft colour blobs, like the app's backdrop.
let blobs: [(NSColor, NSPoint, CGFloat)] = [
    (c(0x7c5cff, 0.42), NSPoint(x: 290, y: 740), 430),
    (c(0x00c8ff, 0.36), NSPoint(x: 760, y: 280), 430),
    (c(0xff5cc8, 0.26), NSPoint(x: 540, y: 560), 320),
]
for (col, pt, r) in blobs {
    NSGradient(colors: [col, col.withAlphaComponent(0)])!
        .draw(fromCenter: pt, radius: 0, toCenter: pt, radius: r, options: [])
}
cg.restoreGState()

// The orb.
let center = NSPoint(x: 512, y: 512)
let R: CGFloat = 248
cg.saveGState()
bgPath.addClip()
NSGradient(colors: [c(0x7c5cff, 0.6), c(0x00c8ff, 0.3), c(0x000000, 0)])!
    .draw(fromCenter: center, radius: R * 0.85, toCenter: center, radius: R * 1.7, options: [])
cg.restoreGState()

let stops: [(CGFloat, NSColor)] = [(0, c(0x7c5cff)), (0.34, c(0xff5cc8)), (0.67, c(0x00c8ff)), (1, c(0x7c5cff))]
func colorAt(_ t: CGFloat) -> NSColor {
    for i in 0..<(stops.count - 1) {
        let (t0, c0) = stops[i], (t1, c1) = stops[i + 1]
        if t >= t0 && t <= t1 {
            let f = (t - t0) / (t1 - t0)
            return c0.blended(withFraction: f, of: c1) ?? c0
        }
    }
    return stops[0].1
}
cg.saveGState()
NSBezierPath(ovalIn: NSRect(x: center.x - R, y: center.y - R, width: 2 * R, height: 2 * R)).addClip()
let n = 720
for i in 0..<n {
    let a0 = CGFloat(i) / CGFloat(n) * 360
    let a1 = CGFloat(i + 2) / CGFloat(n) * 360
    let p = NSBezierPath()
    p.move(to: center)
    p.appendArc(withCenter: center, radius: R + 4, startAngle: a0 + 90, endAngle: a1 + 90)
    p.close()
    colorAt(CGFloat(i) / CGFloat(n)).setFill()
    p.fill()
}
// Highlight and rim shading give it depth.
let hl = NSPoint(x: center.x - 85, y: center.y + 95)
NSGradient(colors: [c(0xffffff, 0.95), c(0xffffff, 0.18), c(0xffffff, 0)])!
    .draw(fromCenter: hl, radius: 0, toCenter: hl, radius: R * 0.98, options: [])
NSGradient(colors: [c(0x000000, 0), c(0x000000, 0.28)])!
    .draw(fromCenter: center, radius: R * 0.68, toCenter: center, radius: R, options: [])
cg.restoreGState()

NSGraphicsContext.restoreGraphicsState()
let png = rep.representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
