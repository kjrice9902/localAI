#!/bin/zsh
# Local AI - build script. Created by Claude (Anthropic).
#
# Compiles main.swift and copies Info.plist, server.py, the UI and the icon
# into /Applications/Local AI.app. The bundled Ollama (Contents/Resources/bin)
# stays inside the app; it is not part of this source folder.
#
# Quit the app first, then:   ./build.sh
set -e
SRC="${0:A:h}"
APP="/Applications/Local AI.app"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -target arm64-apple-macos13.0 "$SRC/main.swift" -o "$TMP/LocalAI" -module-cache-path "$TMP/mc" \
  -framework Cocoa -framework WebKit -framework Speech -framework AVFoundation -framework PDFKit -framework LocalAuthentication -framework Carbon -framework ServiceManagement
swiftc -O -target arm64-apple-macos13.0 "$SRC/pdftext.swift" -o "$TMP/pdftext" -module-cache-path "$TMP/mc" -framework PDFKit -framework Vision -framework AppKit
# Check the plist and the Python files too, so a broken one never ships.
plutil -lint -s "$SRC/Info.plist"
/usr/bin/python3 -I -c 'import ast,sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' "$SRC/Resources/server.py" "$SRC/Resources/doc_clean.py"
# Both compiled: only now touch the app. Remove the old programs first, so the new
# ones are new files (macOS remembers the signature state of a file it has seen).
rm -f "$APP/Contents/MacOS/LocalAI" "$APP/Contents/MacOS/pdftext"
cp "$TMP/LocalAI" "$APP/Contents/MacOS/LocalAI"
# Helper programs belong in Contents/MacOS and need their own signature, or
# macOS kills them on launch ("Code Signature Invalid").
cp "$TMP/pdftext" "$APP/Contents/MacOS/pdftext"
rm -f "$APP/Contents/Resources/pdftext"
cp "$SRC/Info.plist" "$APP/Contents/Info.plist"
cp "$SRC/Resources/server.py" "$APP/Contents/Resources/server.py"
cp "$SRC/Resources/doc_clean.py" "$APP/Contents/Resources/doc_clean.py"
rm -rf "$APP/Contents/Resources/ui"
cp -R "$SRC/Resources/ui" "$APP/Contents/Resources/ui"
if [ -f "$SRC/Resources/LocalAI.icns" ]; then
  cp "$SRC/Resources/LocalAI.icns" "$APP/Contents/Resources/LocalAI.icns"
fi
# Leftovers from the old Qwen Local build.
rm -f "$APP/Contents/MacOS/Qwen" "$APP/Contents/Resources/Qwen.icns" \
      "$APP/Contents/Resources/server.py.bak" "$APP/Contents/Resources/ui/index.html.bak"

xattr -cr "$APP"
codesign --force -s - --identifier local.claude.localai.pdftext "$APP/Contents/MacOS/pdftext"
xattr -cr "$APP"          # signing the helper can leave attributes the app signature rejects
codesign --force -s - "$APP"
xattr -c "$APP"           # Finder info on the bundle folder fails strict checks
codesign --verify --deep --strict "$APP"
touch "$APP"
rm -rf "$TMP"
echo "built $APP"
