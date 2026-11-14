# Local AI

A private chat app for the Mac that runs open AI models on the Mac's own chip.
Chats, files and pictures stay on the computer. The only things that go online
are a web search you turn on yourself (it sends the first 300 characters of your
message to the search service) and a chat where you turn on the Internet chip.

Created and maintained by Claude (Anthropic's AI), November 2026.

> **This repo holds the source code only.** The AI models (about 25 GB) and your
> own chats and settings are not here. GitHub can't hold files that big, and your
> chats are private. The sections below say how to get each one.

## What you need

- A Mac with Apple Silicon (M1 or newer), macOS 13 or later. 16 GB of RAM is enough.
- About 30 GB of free disk space for the models.
- Xcode Command Line Tools, for `swiftc` and `/usr/bin/python3`: run `xcode-select --install`.
- For pictures and the code sandbox only: Python 3.13 from [python.org](https://www.python.org/downloads/macos/)
  (the signed installer, which puts it in `/Library/Frameworks`).

## 1. Build the app

```bash
git clone https://github.com/kjrice9902/localAI.git
cd localAI
./build.sh
```

`build.sh` compiles `main.swift` and `pdftext.swift`, checks `Info.plist` and the
Python files, copies everything into `/Applications/Local AI.app` and signs it.

## 2. Add the model server (Ollama)

The app runs its own private copy of Ollama on port 11435, so it never mixes with
another Ollama you might have installed. That copy lives inside the app and isn't
in this repo (it's about 490 MB).

1. Download **Ollama 0.40.15 for macOS** (`ollama-darwin.tgz`) from
   <https://github.com/ollama/ollama/releases/tag/v0.40.15>.
2. Unpack it into the app:

```bash
mkdir -p "/Applications/Local AI.app/Contents/Resources/bin"
tar -xzf ~/Downloads/ollama-darwin.tgz -C "/Applications/Local AI.app/Contents/Resources/bin"
```

   To make sure the download is genuine, `shasum -a 256 ~/Downloads/ollama-darwin.tgz`
   should print `607c79d5d6315ef9d896db83adde736a4c0057196329843544e79b95afb260a8`.
3. Check that `/Applications/Local AI.app/Contents/Resources/bin/ollama` now exists,
   then run `./build.sh` again so the app is re-signed with Ollama inside.

## 3. Get the chat models (about 15 GB)

| Model | Maker (license) | Ollama tag | Download |
|---|---|---|---|
| Qwen 3.5 9B | Alibaba (Apache 2.0) | `qwen3.5:9b` | 7.6 GB |
| Gemma 4 12B, MLX build | Google (Apache 2.0) | `gemma4:12b-mlx` | 7.7 GB |

**Easiest:** open Local AI. If a model is missing, a banner offers to download it.
Click **Download**.

**Or from Terminal:** quit the app first, then run:

```bash
export OLLAMA_HOST=127.0.0.1:11435
export OLLAMA_MODELS="$HOME/Library/Application Support/LocalAI/models"
OLLAMA="/Applications/Local AI.app/Contents/Resources/bin/ollama"
"$OLLAMA" serve &
sleep 3
"$OLLAMA" pull qwen3.5:9b
"$OLLAMA" pull gemma4:12b-mlx
kill %1
```

Use MLX builds only. The Ollama inside the app has only the MLX runner, so GGUF
builds fail with "llama-server binary not found".

## 4. Get the picture models (optional, about 11 GB)

Picture making uses **mflux 0.22.0** with two 4-bit MLX models from Hugging Face.
The exact versions are pinned below, and the checksums are in `setup/imagegen/`.

| Folder the app looks for | Hugging Face repo | Revision | Size |
|---|---|---|---|
| `imagegen/z-image-turbo-q4` (new pictures) | `mflux-community/z-image-turbo-mflux-q4` | `f427e257d8e6ffa03edd4d9ac554a05809da456c` | 5.5 GB |
| `imagegen/flux2-klein-4b-q4` (editing pictures) | `mflux-community/flux2-klein-4b-mflux-q4` | `794cd159538149ad9830848508c31f0ea7088e58` | 4.3 GB |

Z-Image Turbo is by Alibaba and FLUX.2 Klein 4B is by Black Forest Labs. Both are Apache 2.0.

```bash
D="$HOME/Library/Application Support/LocalAI/imagegen"
mkdir -p "$D"
PY=/Library/Frameworks/Python.framework/Versions/3.13/bin/python3

# The private Python environment the app runs pictures with (exact versions + hashes)
"$PY" -m venv "$D/venv"
"$D/venv/bin/pip" install --require-hashes -r setup/imagegen/requirements.lock

# The two models, at the pinned revisions
"$D/venv/bin/hf" download mflux-community/z-image-turbo-mflux-q4 \
  --revision f427e257d8e6ffa03edd4d9ac554a05809da456c --local-dir "$D/z-image-turbo-q4"
"$D/venv/bin/hf" download mflux-community/flux2-klein-4b-mflux-q4 \
  --revision 794cd159538149ad9830848508c31f0ea7088e58 --local-dir "$D/flux2-klein-4b-q4"

# Check every file against the saved checksums (each line should end in OK)
cp setup/imagegen/z-image-turbo-q4/{REVISION,SHA256SUMS} "$D/z-image-turbo-q4/"
cp setup/imagegen/flux2-klein-4b-q4/{REVISION,SHA256SUMS} "$D/flux2-klein-4b-q4/"
(cd "$D/z-image-turbo-q4" && shasum -a 256 -c SHA256SUMS)
(cd "$D/flux2-klein-4b-q4" && shasum -a 256 -c SHA256SUMS)
```

If the `hf` command is missing, run `"$D/venv/bin/pip" install huggingface_hub`
first. Restart Local AI afterwards, and the picture button appears.

## 5. The code sandbox libraries (optional, about 200 MB)

When the AI runs Python for you (charts, spreadsheets), it uses its own environment:

```bash
P="$HOME/Library/Application Support/LocalAI/pyenv"
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m venv "$P"
"$P/bin/pip" install --require-hashes -r setup/pyenv/requirements.lock
```

## Your own files: chats, settings, pictures

Everything the app creates is stored on your Mac, never in this repo:

```
~/Library/Application Support/LocalAI/
  settings.json     your settings
  threads/          your chats (one .json file each)
  images/ docs/ audio/   pictures, documents and clips you added
  models/           chat models (step 3)
  imagegen/         picture models + their Python (step 4)
  pyenv/            code sandbox libraries (step 5)
  server.log, ollama.log   logs from the last run
```

The `Library` folder is hidden. In Finder, press **Cmd+Shift+G** and paste
`~/Library/Application Support/LocalAI`.

**To move your chats to another Mac:**
- **Recommended:** in Local AI open **Settings → Privacy & storage → Back up…**.
  That saves one zip with your chats, settings and attachments, without the
  models. On the other Mac use **Restore…** in the same place. Every file is
  checked again when it's restored.
- **Or copy the whole folder:** quit the app, copy
  `~/Library/Application Support/LocalAI` to a drive, and put it back at exactly
  the same path on the other Mac. That includes the models (about 26 GB). The
  `imagegen/venv` and `pyenv` environments only work if the other Mac has the
  same macOS username and Python 3.13. If not, redo steps 4 and 5.

## Rebuilding after changes

Quit the app, then run `./build.sh`. To redraw the icon:

```bash
swiftc icon.swift -o icongen && ./icongen icon_1024.png
mkdir -p LocalAI.iconset
for s in 16 32 128 256 512; do sips -z $s $s icon_1024.png --out LocalAI.iconset/icon_${s}x${s}.png; sips -z $((s*2)) $((s*2)) icon_1024.png --out LocalAI.iconset/icon_${s}x${s}@2x.png; done
iconutil -c icns LocalAI.iconset -o Resources/LocalAI.icns
```

## Files

- `main.swift`: the native window and menus, Touch ID lock, dictation and read
  aloud, and the two helper processes (Ollama and the Python server).
- `pdftext.swift`: reads PDFs, Word, RTF, OpenDocument and web files, keeping
  only text a person can actually see.
- `Resources/server.py`: local server on 127.0.0.1:7861. Serves the UI, stores
  chats and settings, talks to Ollama, makes pictures and runs code in a sandbox.
- `Resources/doc_clean.py`: removes Word, RTF and OpenDocument "hidden text"
  before a file is read.
- `Resources/ui/index.html`: the whole chat interface.
- `Info.plist`, `icon.swift`, `build.sh`: app metadata, the icon, the build.
- `setup/`: pinned package lists and model checksums for steps 4 and 5.
