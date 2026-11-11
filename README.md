# GppVerdict: Mining Google Play Protect Verdicts on Delisted Android Apps

Artifact of the paper *GppVerdict: Mining Google Play Protect Verdicts on Delisted Android
Apps*. Google Play Protect does not publish its per-app verdicts: a verdict only appears on
the device where an app is installed. GppVerdict collects them at scale. It installs apps
on an Android device with the app verifier enabled, records the dialog that Google Play
Protect displays when it blocks an installation, and cross-checks the flagged apps with
VirusTotal.

## The study in brief

We installed 10,500 apps that AndroZoo collected from 2020 to 2026 (1,500 per year) and
that have since been removed from Google Play, on a Google Pixel 9a with the app verifier
enabled.

- Google Play Protect blocked **5,346 apps (50.9%)**, but 5,257 of these blocks (98.3%)
  concern the age of the app: the message says that it "was built for an older version of
  Android", and it was shown only for apps that target SDK version 33 or lower.
- Only **89 apps** were blocked because of their behavior: **63 as harmful** and **26 as
  unsafe**. For 54 of them, the message names the threat, e.g., unauthorized charges on
  the mobile bill, spying on personal data, or advertising fraud.
- **79 of these 89 apps have no detection in their VirusTotal reports.**

`python stats.py` recomputes the installation figures from the released results.

## Released data

| Path | Content |
|---|---|
| `study_input_shas.csv` | The 10,500 sampled APKs (`catalog_year`, `sha256`) |
| `output/results.csv` | One row per installation: outcome, category of the Google Play Protect dialog (if any), target SDK version, VirusTotal detections recorded in AndroZoo, … |
| `output/alerts.csv` | One row per dialog: title, message (`body`), buttons, action taken |
| `output/notifications.csv` | Google Play notifications seen during the installations (none carries a verdict) |
| `report/harmful_vs_vt.csv` | The 89 apps blocked as harmful or unsafe, with the message of their dialog and the detections in their VirusTotal reports |
| `vt_out/` | The raw VirusTotal reports of these 89 APKs (`<sha256>.json`) |
| `vt_apks_summary.csv` | The per-APK summary written by `vt_lookup.py` |

Every file identifies an app by the SHA-256 of its APK. The 89 APKs are live malware and
are not in this repository; they are available on Zenodo (restricted access, see the
paper).

## From the paper to the code

The collection process of the paper has three phases:

1. **Sample collection.** The removed apps are the Google Play apps of AndroZoo that no
   longer appear in Google Play's sitemaps. We do not publish this list, only the sample
   that the study drew from it: `study_input_shas.csv`. `sample_years.py` draws such a
   sample from a list of removed apps in AndroZoo's catalog format, which you build
   yourself (`Data/gone_apps.tsv` by default).
2. **Google Play Protect responses.** `collect.py` downloads each APK from AndroZoo,
   installs it with the app verifier enabled, records the install-time dialog, and
   uninstalls the app; `run.py` does the same for a local folder of APKs.
   `install_flagged.py` re-installs blocked apps with the verifier for USB installs turned
   off and observes the notification that Google Play Protect then displays: in the
   study, the message that Google Play Protect showed in the Google Play app was always
   the same as the install-time one, so the dataset relies on the install-time dialogs
   only.
3. **Cross-validation with VirusTotal.** `vt_lookup.py` retrieves by SHA-256 the most
   recent VirusTotal reports of the 89 apps, without uploading or rescanning them, and
   `harmful_vs_vt.py` joins them with the dialogs. For the other 10,411 apps, the paper
   uses the detections recorded in AndroZoo (`vt_detection`).

## Setup (once)

1. **Phone** — Developer options → enable *USB debugging* and, if present,
   *Verify apps over USB* (the app verifier whose dialogs GppVerdict records). Turn off
   the screen lock (no PIN).
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

Streams an AndroZoo catalog (possibly inside a `.tar.gz`), downloads each APK from
AndroZoo, installs it with the app verifier enabled, records the Play Protect dialog
(texts and screenshot), the Google Play notifications and the logcat, then uninstalls
the app. Results are stored like `run.py`'s, plus the VirusTotal detection count
recorded in the catalog. In the examples, `Data/gone_apps.tsv` stands for your own list
of removed apps (not published).

```bash
# Stratified sample by VirusTotal detection count, recent and not too big, no upload
python collect.py --catalog Data/gone_apps.tsv --out results_az \
    --per-bucket 5 --buckets vt15+ vt5-14 --max-size-mb 60 --year-min 2020 --no-scan

# Process the whole catalog, resumable (very long run — use the robust wrapper below)
python collect.py --catalog Data/gone_apps.tsv --out results_all --all --no-scan --resume
```

VirusTotal detection buckets, as in the paper: `vt0` (no detection), `vt1-4`, `vt5-14`,
`vt15+`. A `vt0` app is not necessarily benign: most of the apps that Google Play Protect
blocked as harmful or unsafe are in `vt0`.

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
# The paper's design: 1,500 apps per year, 2020-2026 (its exact sample: study_input_shas.csv)
python sample_years.py --catalog Data/gone_apps.tsv \
    --per-year 1500 --year-min 2020 --year-max 2026 --seed 1 \
    --out-tsv Data/sample.tsv --out-csv report/sample.csv

# Draw a new sample that excludes the apps already processed (here, the study's)
python sample_years.py --per-year 500 --seed 2 --exclude output \
    --out-tsv Data/sample_b.tsv --out-csv report/sample_b.csv
```

### 4. Re-installing blocked apps — `install_flagged.py`

`collect.py` never forces a flagged install. `install_flagged.py` does the opposite,
**deliberately**: it re-installs APKs that Play Protect blocked at install time and
observes what Play Protect does once the app is present (the notification it shows,
automatic removal, …). The paper used it to check that the message Google Play Protect
then shows in the Google Play app is the same as the install-time one.

This requires *"Verify apps over USB"* **OFF** and the **phone online** (the
background scan of installed apps is a cloud operation). The tool changes no
settings — you drive the phone.

```bash
python install_flagged.py --source output --categories harmful unsafe   # the 89 apps
python install_flagged.py --sha256 f828c1e2... --observe 600 --keep-installed
```

Without `--categories`, every app that got an alert is re-installed.

### 5. Installation figures of the paper — `stats.py`

Prints the installation outcomes (with the failure codes), the verdicts of the blocked
apps by VirusTotal detections recorded in AndroZoo, the dialog titles, and the hours in
which Google Play Protect most likely did not check the installed apps.

```bash
python stats.py                    # the study's results, in output/
python stats.py --out results_all  # another run
```

### 6. VirusTotal cross-validation — `vt_lookup.py`, `harmful_vs_vt.py`

`vt_lookup.py` hashes every APK of a folder and retrieves its most recent VirusTotal
report by SHA-256 (`GET /api/v3/files/<sha256>`, allowed with a free API key), without
uploading or rescanning it. The raw reports are cached in `vt_out/` and reused on
re-runs, so the counts date from each file's last VirusTotal analysis
(`vt_last_analysis`). `harmful_vs_vt.py` then joins them with the dialogs of the 89
harmful or unsafe apps into `report/harmful_vs_vt.csv`.

```bash
export VT_KEY=...       # or put the key in .vt_key (git-ignored)
python vt_lookup.py --apks path/to/harmful_unsafe_apks   # the 89 APKs from Zenodo -> vt_out/
python harmful_vs_vt.py                                  # output/ + vt_out/ -> report/harmful_vs_vt.csv
```

A free key allows 4 lookups per minute, so the 89 lookups take about 25 minutes; the
script waits out the rate limit, and a re-run resumes after an interruption.

---

## Outputs

```
results/
├── results.csv         # one row per APK
├── alerts.csv          # one row per Play Protect dialog
├── notifications.csv   # one row per Google Play notification
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
in the CSV), referenced by `logcat_path`. The study's results in `output/` keep the three
CSV files only.

**`outcome` values** (label in the paper's outcome table)

- `blocked_by_play_protect` — *Blocked by Google Play Protect*: a dialog appeared and the
  app was not installed.
- `installed_no_alert` — *Installed without alert*.
- `installed_after_alert` — *Installed after alert*: a dialog appeared but the app
  installed anyway.
- `install_failed` — *Installation failed*, without any dialog; the code is in
  `install_failure_code`: `INSTALL_FAILED_MISSING_SPLIT` (only the base APK of a split
  app), `INSTALL_FAILED_NO_MATCHING_ABIS` (native code for another CPU architecture),
  `INSTALL_FAILED_VERIFICATION_FAILURE`, `INSTALL_FAILED_DEPRECATED_SDK_VERSION`,
  `INSTALL_PARSE_FAILED_MANIFEST_MALFORMED`, or none.
- `timeout`, `timeout_after_alert` — *Timed out without / after alert*.
- `download_failed`, `error` — processing errors (`collect.py`).

> In `output/results.csv`, one record was corrected by hand: `9782c8f1…`
> (`com.offline.sinfjahontarixi8`) showed a *Harmful app blocked* dialog and was never
> installed, but the install command then timed out. It is counted as
> `blocked_by_play_protect`, as in the paper.

**`category` values** (per dialog): `harmful`, `old_target_sdk`, `unsafe`,
`unverified_developer`, `scan_prompt`, `no_problem_found`, `progress`, `other`;
`primary_category` in `results.csv` is the main one of each app. Classification uses
English/French keywords in `gppverdict/classifier.py`; the raw texts (`texts_json`) are
always kept, so you can refine the rules.

> `old_target_sdk` is the paper's *outdated target SDK* message ("This app was built for
> an older version of Android and doesn't include the latest privacy protections"). It is
> a targetSdk block, not necessarily a malware detection: in the study, it was shown only
> for apps that target SDK version 33 or lower. It comes with the title *Unsafe app
> blocked*, like the `unsafe` messages, so label apps by `category`, never by the dialog
> title.

> An app installed without an alert was not necessarily checked by Google Play Protect:
> in 28 hours of the study (October 29 – November 6, 2026, UTC), it most likely did not
> check the 2,058 apps installed without an alert. `stats.py` lists these hours; use
> `created_at` to find the apps.

**`vt_detection` / `vt_bucket`** (`results.csv`): the number of antivirus engines that
flag the APK on VirusTotal, as recorded in the AndroZoo catalog, and its bucket.

**`report/harmful_vs_vt.csv`**: one row per app blocked as harmful or unsafe, with the
Play Protect verdict (`pp_verdict`, `pp_alert_title`, `pp_alert_body`, `pp_test_date`),
the detections recorded in AndroZoo (`az_vt_detection`, `az_vt_bucket`), and the
VirusTotal report: `vt_malicious` (engines that flag the APK), `vt_engines` (engines with
a verdict), `vt_bucket`, `vt_threat_label`, `vt_detections` (each flagging engine and its
label), `vt_last_analysis` and `vt_first_submission`.

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
install_flagged.py          # deliberately re-install blocked apps and observe Play Protect
stats.py                    # the paper's installation figures from a run's results.csv
vt_lookup.py                # VirusTotal reports of a folder of APKs, by SHA-256
harmful_vs_vt.py            # the harmful/unsafe apps with their VirusTotal reports
gppverdict/
├── catalog.py              # AndroZoo catalog reader + stratified sampling
├── androzoo.py             # AndroZoo download client (by sha256, cached)
├── device.py               # adb wrapper (device info, packages, uninstall)
├── installer.py            # async adb install (blocks while the dialog is shown)
├── watcher.py              # detect / extract / dismiss dialogs (uiautomator2)
├── notifications.py        # notifications of the Play Protect packages (dumpsys notification)
├── logcat.py               # logcat capture + filtered extract
├── static.py               # sha256 + APK metadata (androguard)
├── classifier.py           # alert category + outcome
└── storage.py              # CSV storage (no database)
scripts/
├── run-robust.sh           # resumable, drop-tolerant long-run wrapper
└── status.sh               # progress + per-year block-rate health snapshot
study_input_shas.csv        # the study's sample (10,500 APKs)
output/                     # the study's results (results.csv, alerts.csv, notifications.csv)
report/harmful_vs_vt.csv    # the 89 harmful/unsafe apps and their VirusTotal reports
vt_out/                     # raw VirusTotal reports of the 89 APKs
vt_apks_summary.csv         # vt_lookup.py's per-APK summary
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
