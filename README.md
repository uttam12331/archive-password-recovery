# Archive Password Recovery

A desktop tool to recover passwords for **RAR** and **PDF** files you own or are
authorized to open. It's a clean graphical front-end over the **hashcat** engine —
same category as tools like Passware or Accent RAR Recovery, but free and open.

Windows desktop app. The UI is a local web front-end rendered in a native window
(pywebview + Edge WebView2); the recovery work is done by hashcat.

## Features

- **File picker** — choose a `.rar` or `.pdf`; it auto-detects the format and
  extracts the crack hash. Both are read **natively** (RAR5 by parsing the
  archive, PDF by reading its encryption dictionary) — no external helper scripts.
- **Two attacks**
  - *Brute force* — build the exact character set with a per-character keyboard
    (lowercase, uppercase, digits, and every special character), set a length
    range, and it tries every combination.
  - *Wordlist* — point it at a `.txt` list, optionally with `best64` mutation rules.
- **CPU / GPU / Both** — pick the compute device (auto-disables what isn't present).
- **Intensity** — Low → Max, to stay gentle on the machine while other work runs.
- **Pause / Resume / Stop** — pause writes a checkpoint (hashcat `--session` +
  `--restore`); resume continues from it.
- **Live status** — speed, progress %, exact time remaining, estimated finish
  clock, and the recovered password (with copy).

## Requirements

- Windows 10/11 (uses the Edge **WebView2** runtime, preinstalled on Win11)
- Python 3.10+
- A copy of **hashcat 7.x** (not included — see Setup)

## Setup (run from source)

```bash
pip install pywebview pypdf cryptography
```

Then add the hashcat engine:

1. Download **hashcat 7.x** (binaries) from <https://hashcat.net/hashcat/>.
2. Extract it so that **`hashcat/hashcat.exe`** sits next to `app.py`.
3. Make sure **`hashcat/best64.rule`** exists (copy it from the engine's
   `rules/best64.rule`) — only needed for the wordlist "common variations" option.

Run it:

```bash
python app.py
```

## Build a standalone .exe + installer

```bash
pip install pyinstaller pillow
build_exe.bat
```

- Output: `dist\ArchiveRecovery\ArchiveRecovery.exe` — ship the whole
  `ArchiveRecovery` folder (the exe plus `ui/` and `hashcat/` beside it).
- For the installer, install [Inno Setup 6](https://jrsoftware.org/isdl.php) and
  compile `installer.iss` → `Output\ArchiveRecovery-Setup.exe`.
- The app icon is `appicon.ico` (regenerate from `scripts`/Pillow if you wish).

## How it works

- `app.py` — pywebview window + a small JS↔Python API bridge; `ui/index.html` is
  the whole interface.
- `engine.py` — builds and runs hashcat (mode 13000 for RAR5, 10400–10700 for
  PDF), extracts hashes natively, and streams live status back to the UI.

## Honest limits

- RAR5 and modern PDFs use AES — there is **no shortcut**; recovery means
  guessing. Short or common passwords fall quickly; long random ones are not
  practically recoverable, no matter the GPU.
- Estimates before a run are rough; the live time once running is hashcat's real
  figure.

## Authorized use only

Use this only on files you own or have explicit permission to access. Recovering
passwords for files you are not authorized to open may be illegal.

## License

MIT — see [LICENSE](LICENSE).
