# GppVerdict: Mining Google Play Protect Verdicts

Artifact for the paper. It holds the pipeline that installs Android apps, extracts their Google Play Protect verdicts from an Android device, and it cross-checks malicious apps with VirusTotal. Apps are preselected from AndroZoo.

## Setup (once)

1. **Phone** — Developer options → enable *USB debugging* and, if present,
   *Verify apps over USB*. Turn off the screen lock (no PIN).
2. **Computer** — install
   [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools)
   (for `adb`) and Python 3.9+.
3. **Project**:
   ```bash
   pip install -r requirements.txt
   adb devices           # the phone must show up as "device"
   ```
   The uiautomator2 agent installs itself on the phone on first connection
   (on an older uiautomator2, run `python -m uiautomator2 init`).

### API key

Put your AndroZoo API key in a file named `.androzoo_key` at the project root
(or pass `--apikey`). It is read automatically and is git-ignored.

```bash
cp .androzoo_key.example .androzoo_key
# then edit .androzoo_key and paste your key
```

---

## Usage

### 1. Local folder of APKs — `run.py`

```bash
# Smoke test on 3 APKs
python run.py --apks /path/to/apks --out results --limit 3

# Whole folder (recursive), resumable after an interruption
python run.py --apks /path/to/apks --out results --recursive --resume
```

| Option | Effect |
|---|---|
| `--serial XXXX` | pick the device when several are attached |
| `--adb PATH` | path to `adb` if not on `PATH` |
| `--timeout 150` | per-APK timeout (seconds) |
| `--no-scan` | refuse uploading the APK to Google |
| `--full-logcat` | keep the full logcat in addition to the filtered extract |
| `--keep-installed` | do not uninstall after the test |
| `--export-only` | print where the CSV files are and exit |

`Ctrl+C` stops cleanly; resume with `--resume`.

### 2. AndroZoo pipeline — `collect.py`

Streams a catalog (e.g. `gone_apps.tsv`, possibly inside a `.tar.gz`), downloads each
APK from AndroZoo, installs it, captures the Play Protect alert (dialog **and**
notification, screenshot, logcat), then uninstalls. Stored in the same database as
`run.py`, plus the VirusTotal detection count from the catalog.

```bash
# Stratified sample by VirusTotal detection count, recent and not too big, no upload
python collect.py --catalog Data/gone_apps.tsv --out results_az \
    --per-bucket 5 --buckets vt15+ vt5-14 --max-size-mb 60 --year-min 2020 --no-scan

# Process the whole catalog, resumable (very long run — use the robust wrapper below)
python collect.py --catalog Data/gone_apps.tsv --out results_all --all --no-scan --resume
```

VirusTotal detection buckets: `vt0` (clean), `vt1-4`, `vt5-14`, `vt15+` (likely
malware).

| Option | Effect |
|---|---|
| `--catalog PATH` | AndroZoo catalog (`.tsv`, `.csv`, `.gz`, `.tar.gz`) |
| `--per-bucket N` | APKs drawn per bucket (default 10) |
| `--buckets vt15+ vt5-14` | which buckets to include (default: all) |
| `--max-size-mb 60` | skip APKs larger than N MB |
| `--year-min / --year-max` | filter by year added |
| `--seed 1` | sampling seed (reproducible) |
| `--all` | process the **whole** catalog in file order (use with `--resume`) |
| `--sha256 H1 H2 …` | test specific hashes instead of sampling |
| `--apikey KEY` | AndroZoo key (otherwise read from `.androzoo_key`) |
| `--keep-apks` | keep the downloaded APKs (otherwise deleted after each test) |

Downloaded APKs are cached in `<out>/apks/` only for the duration of the test, then
deleted (unless `--keep-apks`), so disk stays small even on a large run. `collect.py`
also accepts `run.py`'s install options (`--serial`, `--timeout`, `--no-scan`,
`--keep-installed`, `--resume`, `--export-only`, …).

### 3. Year-stratified sampling — `sample_years.py`

Draws a random, reproducible sample of *N* APKs per year from an AndroZoo catalog
(reservoir sampling, single streaming pass). Writes a TSV sub-catalog that
`collect.py` consumes directly, plus a readable CSV manifest.

```bash
python sample_years.py --catalog Data/gone_apps.tsv \
    --per-year 500 --year-min 2020 --year-max 2026 --seed 1 \
    --out-tsv Data/sample.tsv --out-csv report/sample.csv

# Draw a second sample that excludes everything already processed
python sample_years.py --per-year 500 --seed 2 \
    --exclude results_sample results_all \
    --out-tsv Data/sample_b.tsv --out-csv report/sample_b.csv
```

### 4. Re-installing flagged apps — `install_flagged.py`

`collect.py` never forces a flagged install. `install_flagged.py` does the opposite,
**deliberately**: it re-installs APKs Play Protect already blocked
(`harmful` / `unsafe`) and observes what Play Protect does once the app is present
(the "Harmful app found" notification, automatic removal, …).

This requires *"Verify apps over USB"* **OFF** and the **phone online** (the
background scan of installed apps is a cloud operation). The tool changes no
settings — you drive the phone.

```bash
python install_flagged.py                       # harmful/unsafe from results_all/
python install_flagged.py --sha256 f828c1e2... --observe 600 --keep-installed
```

### 5. Quick tally — `stats.py`

```bash
python stats.py --out results_all
```

---

## Outputs

```
results/
├── results.csv         # one row per APK
├── alerts.csv          # one row per Play Protect dialog
├── notifications.csv   # one row per Play Protect notification
├── runs.csv            # one row per run (device info + argv)
├── screenshots/        # <sha256[:16]>_<n>.png (dialog), <sha256[:16]>_notif.png (shade)
├── apks/               # downloaded-APK cache (collect.py; emptied unless --keep-apks)
└── logcat/             # <sha256[:16]>.log (filtered extract)
```

There is **no database**: the CSV files are the source of truth, appended after every
APK so they are always complete even if the run is cut. `result_id` links alerts and
notifications back to their result row, and `sha256` is duplicated into every file so
each one is usable on its own. A resumed run reads `results.csv` to skip what is
already done. The 20k-char logcat excerpt is kept as a file under `logcat/` (not inline
in the CSV), referenced by `logcat_path`.

**`outcome` values**

- `blocked_by_play_protect` — an alert appeared and the install failed.
- `installed_after_alert` — an alert appeared but the app installed anyway (e.g. a
  scan found nothing).
- `installed_no_alert` — no alert, app installed.
- `install_failed` — install failed with no alert; the code is in
  `install_failure_code` (e.g. `INSTALL_FAILED_DEPRECATED_SDK_VERSION`).
- `timeout`, `timeout_after_alert`, `error` — incomplete or errored.

**`category` values** (per alert): `harmful`, `old_target_sdk`, `unsafe`,
`unverified_developer`, `scan_prompt`, `no_problem_found`, `progress`, `other`.
Classification uses English/French keywords in `gppverdict/classifier.py`; the raw
texts (`texts_json`) are always kept, so you can refine the rules.

> The *"built for an older version of Android"* alert is a **targetSdk** block, not
> necessarily a malware detection. Cross-check `category` against `target_sdk` and
> external labels (VirusTotal, AVClass).

---

## If alerts aren't detected

- Button labels depend on the phone's language — add yours to `DISMISS_LABELS` /
  `SCAN_LABELS` in `gppverdict/watcher.py`.
- Inspect what the tool reads while a dialog is up:
  ```bash
  python -c "import uiautomator2 as u2; print(u2.connect().dump_hierarchy())"
  ```
- If no alert ever appears over ADB, check
  `adb shell settings get global verifier_verify_adb_installs` (should be `1`).

---

## Project structure

```
run.py                      # CLI for a local APK folder + main loop
collect.py                  # AndroZoo pipeline (sample → download → install → capture)
sample_years.py             # year-stratified reservoir sampler over an AndroZoo catalog
install_flagged.py          # deliberately re-install flagged apps and observe Play Protect
stats.py                    # quick tally from a run's results.csv
gppverdict/
├── catalog.py              # AndroZoo catalog reader + stratified sampling
├── androzoo.py             # AndroZoo download client (by sha256, cached)
├── device.py               # adb wrapper (device info, packages, uninstall)
├── installer.py            # async adb install (blocks while the dialog is shown)
├── watcher.py              # detect / extract / dismiss dialogs (uiautomator2)
├── notifications.py        # Play Protect notification capture (dumpsys notification)
├── logcat.py               # logcat capture + filtered extract
├── static.py               # sha256 + APK metadata (androguard)
├── classifier.py           # alert category + outcome
└── storage.py              # CSV storage (no database)
scripts/
├── run-robust.sh           # resumable, drop-tolerant long-run wrapper
└── status.sh               # progress + per-year block-rate health snapshot
report/                     # final study reports (PDF) + sample manifests (CSV)
```

---

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this project except in compliance with the License. You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

See the [`LICENSE`](LICENSE) file for the full text.
