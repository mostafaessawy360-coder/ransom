# Ransomware Detector (content-based)

A defensive tool written in pure Python (3.8+, **no third-party packages**) that decides
whether a file looks like it was damaged by ransomware by looking at **what is inside the
file**, not just its name.

## How it works

Every file is sampled (whole file if small, otherwise head + middle + tail, 16 KB each) and
scored from 0 to 100 using several independent signals:

| Signal | Why it matters | Points |
|---|---|---|
| **Shannon entropy** ≥ 7.2 bits/byte on a non-text block | Ciphertext looks like random noise (~8.0); documents/text sit at 4-6 | part of rules below |
| **Magic-number check** | A real `.docx` starts with `PK`, a `.jpg` with `FF D8 FF`... encrypted files lose the header | 60 |
| **Text file that is no longer text** | `.txt/.csv/.py/...` that decodes into garbage | 65 |
| **Partial encryption** | Some blocks text, some random (intermittent encryption) | 40 |
| **Chi-square uniformity** | Every byte value appears equally often, as in ciphertext | +10 |
| **Broken zip container** | `.docx/.xlsx/.pptx` whose zip directory is damaged | 30 |
| **Ransom-note text** | Several patterns: "files encrypted", crypto payment demand, `.onion` address, deadlines... | up to 70 |
| **Known ransomware extension** | `.lockbit`, `.wncry`, `.locked`, ... | 35 |
| **Appended extension / victim tag** | `budget.xlsx.locked`, `photo.jpg.id-1A2B3C4D.[mail@x.com].ext` | 20 / 25 |
| **Ransom-note file name** | `HOW_TO_RECOVER_FILES.txt` | 30 |

A file with a **valid header** (real PNG, JPG, ZIP, MP4...) is *not* penalised for high entropy,
because compressed formats are legitimately random-looking. This is what keeps false positives low.

Verdicts: `CLEAN` (< 30), `SUSPICIOUS` (30-69), `HIGH_RISK` (≥ 70). Thresholds are configurable.

On top of per-file scoring, the scanner raises **campaign alerts** (many files sharing one new
extension, ransom notes in several folders, a large share of files flagged), and the monitor
alerts on **bursts** of suspicious files inside a time window.

## Project layout

```
ransomware-detector/
├── detector/
│   ├── entropy.py      # Shannon entropy, chi-square, text detection
│   ├── magic.py        # file-type identification from header bytes
│   ├── signatures.py   # extensions, filename patterns, ransom-note regexes  <- extend me
│   ├── analyzer.py     # per-file scoring engine
│   ├── scanner.py      # folder scan + campaign-level correlation
│   ├── monitor.py      # real-time folder watcher
│   ├── report.py       # console / JSON / CSV output
│   ├── samples.py      # SAFE test-file generator
│   └── cli.py          # command line interface
├── tests/test_detector.py
└── .vscode/            # launch.json, settings.json, tasks.json
```

## Setup in VS Code

1. Install Python 3.8+ and the **Python** extension in VS Code.
2. `File > Open Folder...` and choose `ransomware-detector`.
3. Open the terminal (`Ctrl+` `` ` ``) and create a virtual environment (optional but tidy):
   ```
   python -m venv .venv
   ```
   Then `Ctrl+Shift+P` > **Python: Select Interpreter** > pick `.venv`.
4. No `pip install` is needed.

## Run it

```bash
python -m detector demo                         # creates demo_samples/ and scans it
python -m detector scan  "C:\Users\you\Documents"
python -m detector scan  ./demo_samples --json report.json --csv report.csv
python -m detector file  ./demo_samples/infected/contract.docx    # explain one file
python -m detector monitor ./some_folder        # real time, Ctrl+C to stop
```

Useful options: `--threshold 30`, `--high-threshold 70`, `--ignore-ext .dat .bin`,
`--exclude folder_name`, `--all` (show clean files too), `--no-color`.
`scan` exits with `0` clean, `1` suspicious, `2` high risk, handy for scripts.

In VS Code you can also press **F5** and choose a launch configuration (Demo, Scan, Monitor,
Explain file) and run the tests from the **Testing** sidebar or `Terminal > Run Task > Run tests`.

### Try the live monitor

Terminal 1: `python -m detector monitor demo_live` (create the folder first)
Terminal 2: `python -m detector.samples demo_live` then watch alerts appear in Terminal 1 and in `alerts.log`.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Safe testing

The sample generator never touches your real files. "Encrypted" samples are just random bytes
(`os.urandom`) saved under document names, and "ransom notes" are harmless text files. Do not
test with real ransomware; use a disposable VM if you ever need to.

## Limitations (please read)

* This is a **heuristic detector**, not antivirus. It finds *encrypted results*, it does not
  stop the process doing the encrypting, and it can be evaded (e.g. encryption that keeps the file
  header intact and uses low-entropy encoding).
* Legitimately encrypted or compressed data **without a known header** (password-protected
  containers, custom game assets, some backups) can score `SUSPICIOUS`. Use `--ignore-ext`.
* The extension and phrase lists are not exhaustive. Add your own in `detector/signatures.py`.
* The monitor uses polling (default every 2 s), so very fast attacks are seen with a small delay.

## Ideas to extend it

* Quarantine or auto-move flagged files, or kill the writing process (`psutil`).
* Instant file events with `watchdog` instead of polling.
* Canary / honeypot files that should never change.
* Machine-learning classifier on byte histograms, or YARA rules for note text.
* A small GUI (Tkinter) or e-mail/Telegram alerts from `Monitor(on_event=...)`.
