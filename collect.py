#!/usr/bin/env python3
"""GppVerdict — AndroZoo → phone pipeline.

For a sample of APKs drawn from an AndroZoo catalog (e.g. gone_apps.tsv): download
each APK from AndroZoo, install it on the attached phone, capture the Play Protect
alert (on-screen dialog + notification + screenshot + logcat), then uninstall and
store everything to CSV.

Safety rule (inherited from the watcher): the tool NEVER clicks "Install anyway" /
"Install without scanning". Use a dedicated phone.

Example:
    python collect.py --catalog "Data/gone-apps.tar.gz" --out results_az \\
        --per-bucket 10 --buckets vt15+ vt5-14 --max-size-mb 60 --year-min 2020 --no-scan
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from gppverdict import catalog, classifier
from gppverdict.androzoo import AndroZoo, AndroZooError, read_api_key
from gppverdict.device import AdbError, Device
from gppverdict.installer import AsyncInstall
from gppverdict.logcat import LogcatCapture
from gppverdict.notifications import NotificationCapture
from gppverdict.static import analyze, sha256_file
from gppverdict.storage import Storage, latest_by_sha
from gppverdict.watcher import UI_CALL_TIMEOUT, call_timeout, watch

try:
    from rich.console import Console
    from rich.progress import (BarColumn, DownloadColumn, MofNCompleteColumn, Progress,
                               SpinnerColumn, TextColumn, TimeElapsedColumn,
                               TimeRemainingColumn, TransferSpeedColumn)
    _RICH = True
except ImportError:  # rich missing: fall back to plain prints
    _RICH = False

PROTECTED_PREFIXES = ("com.github.uiautomator",)
DEFAULT_KEY_FILE = Path(__file__).resolve().parent / ".androzoo_key"


def parse_args():
    p = argparse.ArgumentParser(description="AndroZoo → Play Protect pipeline on a phone.")
    p.add_argument("--catalog", help="AndroZoo catalog (.tsv, .csv, .gz or .tar.gz). "
                   "Required except with --sha256 or --export-only.")
    p.add_argument("--out", default="results_az", help="Output directory (default: results_az)")
    p.add_argument("--apikey", help="AndroZoo API key (otherwise read from .androzoo_key)")
    # Sampling
    p.add_argument("--per-bucket", type=int, default=10,
                   help="Number of APKs per VirusTotal detection bucket (default: 10)")
    p.add_argument("--buckets", nargs="+", choices=[b[0] for b in catalog.BUCKETS],
                   help="Buckets to include (default: all). E.g. vt15+ vt5-14")
    p.add_argument("--max-size-mb", type=float, help="Skip APKs larger than N MB")
    p.add_argument("--year-min", type=int, help="Minimum year added")
    p.add_argument("--year-max", type=int, help="Maximum year added")
    p.add_argument("--seed", type=int, default=1, help="Random sampling seed (default: 1)")
    p.add_argument("--sha256", nargs="+", help="Test these exact sha256 instead of sampling")
    p.add_argument("--all", action="store_true", dest="all_apks",
                   help="Process the WHOLE catalog (in file order), not a sample. The "
                        "--buckets/--max-size-mb/--year-* filters still apply. Use --resume.")
    p.add_argument("--no-precount", action="store_true",
                   help="With --all: skip pre-counting the total (start immediately, no ETA)")
    # Device / install
    p.add_argument("--serial", help="ADB serial number (if several devices)")
    p.add_argument("--adb", default="adb", help="Path to adb if not on PATH")
    p.add_argument("--timeout", type=int, default=150, help="Per-APK timeout in seconds (default: 150)")
    p.add_argument("--grace", type=float, default=4.0, help="Watch window after install (default: 4s)")
    p.add_argument("--pause", type=float, default=2.0, help="Pause between APKs (default: 2s)")
    p.add_argument("--no-scan", action="store_true", help="Do not send the APK to Google for analysis")
    p.add_argument("--bypass-low-target-sdk-block", action="store_true",
                   help="Android 14+: bypass the system block of apps with targetSdk < 24")
    p.add_argument("--keep-installed", action="store_true", help="Do not uninstall after the test")
    p.add_argument("--keep-apks", action="store_true", help="Keep the downloaded APKs (cache)")
    p.add_argument("--full-logcat", action="store_true", help="Also keep the full logcat")
    p.add_argument("--enable-adb-verify", action="store_true",
                   help="Try to enable verifier_verify_adb_installs=1")
    p.add_argument("--resume", action="store_true", help="Skip sha256 already processed")
    p.add_argument("--retest-outcomes", nargs="+", metavar="OUTCOME",
                   help="Replay apps whose last result has this outcome (e.g. "
                        "installed_no_alert) instead of reading the catalog. Useful to redo "
                        "apps tested offline. Each app is reinstalled once online.")
    p.add_argument("--require-online", action="store_true", default=True,
                   help="Wait for the phone to be online before each install (default: on)")
    p.add_argument("--no-require-online", dest="require_online", action="store_false",
                   help="Do not check connectivity before installing")
    p.add_argument("--export-only", action="store_true",
                   help="Print where the CSV files are and exit (the CSVs are the store)")
    return p.parse_args()


# --- Display -------------------------------------------------------------------

class UI:
    """Progress display: rich bars if available, otherwise plain prints."""

    def __init__(self):
        self.console = Console() if _RICH else None
        self.progress = None
        self.overall = None
        self.dl = None

    def log(self, msg: str) -> None:
        (self.console.print if self.console else print)(msg)

    def start(self, total: int | None):
        if not _RICH:
            return
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"), BarColumn(),
            MofNCompleteColumn(), TextColumn("•"), DownloadColumn(), TransferSpeedColumn(),
            TextColumn("•"), TimeElapsedColumn(), TextColumn("ETA"), TimeRemainingColumn(),
            console=self.console, transient=False)
        self.progress.start()
        self.overall = self.progress.add_task("APKs processed", total=total)
        self.dl = self.progress.add_task("Download", total=1, visible=False)

    def download_cb(self):
        def cb(got, total):
            if self.progress:
                self.progress.update(self.dl, completed=got, total=total or got, visible=True)
        return cb

    def download_done(self):
        if self.progress:
            self.progress.update(self.dl, visible=False)

    def advance(self, label: str):
        if self.progress:
            self.progress.advance(self.overall)
            self.progress.update(self.overall, description=label)

    def stop(self):
        if self.progress:
            self.progress.stop()


def sample_catalog(args, ui: UI) -> list[dict]:
    path = Path(args.catalog)
    size = path.stat().st_size
    ui.log(f"Reading catalog [cyan]{path.name}[/] ({size / 1e6:.0f} MB)…"
           if _RICH else f"Reading catalog {path.name} ({size / 1e6:.0f} MB)…")
    if _RICH:
        with Progress(SpinnerColumn(), TextColumn("[bold]Sampling"), BarColumn(),
                      DownloadColumn(), TransferSpeedColumn(), TimeElapsedColumn(),
                      console=ui.console) as prog:
            t = prog.add_task("scan", total=size)
            rows, stats = catalog.sample(
                path, args.per_bucket, args.buckets, args.max_size_mb, args.year_min,
                args.year_max, args.seed, on_read=lambda n: prog.advance(t, n))
    else:
        rows, stats = catalog.sample(path, args.per_bucket, args.buckets, args.max_size_mb,
                                     args.year_min, args.year_max, args.seed)
    ui.log("Buckets: " + ", ".join(
        f"{b}={stats[b]['selected']}/{stats[b]['seen']}" for b in stats))
    return rows


def count_catalog(args, ui: UI) -> int:
    """Pre-pass over the catalog to learn the total (for the --all ETA)."""
    path = Path(args.catalog)
    size = path.stat().st_size
    ui.log("Counting the total (pre-pass over the catalog)…")
    if _RICH:
        with Progress(SpinnerColumn(), TextColumn("[bold]Counting"), BarColumn(),
                      DownloadColumn(), TransferSpeedColumn(), TimeElapsedColumn(),
                      console=ui.console) as prog:
            t = prog.add_task("scan", total=size)
            n = catalog.count(path, args.buckets, args.max_size_mb, args.year_min,
                              args.year_max, on_read=lambda b: prog.advance(t, b))
    else:
        n = catalog.count(path, args.buckets, args.max_size_mb, args.year_min, args.year_max)
    ui.log(f"{n} APKs match the filters.")
    return n


# --- Processing one APK --------------------------------------------------------

def cleanup_screen(d) -> None:
    try:
        call_timeout(d.press, UI_CALL_TIMEOUT, "back")
        call_timeout(d.press, UI_CALL_TIMEOUT, "home")
    except Exception:  # noqa: BLE001
        pass


def shade_screenshot(d, dev, path: Path) -> str | None:
    """Open the notification shade, screenshot it, then collapse it."""
    try:
        dev.shell("cmd statusbar expand-notifications")
        time.sleep(1.0)
        call_timeout(d.screenshot, UI_CALL_TIMEOUT, str(path))
        return str(path)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            dev.shell("cmd statusbar collapse")
        except Exception:  # noqa: BLE001
            pass


def is_online(dev) -> bool:
    """Does the phone have an active default network? Play Protect needs internet to
    analyze: offline, it lets everything through with no alert."""
    try:
        out = dev.shell("dumpsys connectivity", timeout=20)
    except Exception:  # noqa: BLE001
        return False
    return "Active default network:" in out and "Active default network: none" not in out


def wait_online(dev, ui, timeout: float = 1800, poll: float = 5) -> bool:
    """Wait until the phone is online (up to `timeout` s). True if online."""
    if is_online(dev):
        return True
    ui.log("⏳ Phone offline — Play Protect needs internet. Waiting for reconnection…")
    t0 = last = time.time()
    while time.time() - t0 < timeout:
        time.sleep(poll)
        if is_online(dev):
            ui.log(f"✓ Online again after {time.time() - t0:.0f} s.")
            return True
        if time.time() - last > 30:
            ui.log(f"   …still offline ({time.time() - t0:.0f} s).")
            last = time.time()
    return False


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def retest_rows(db: Storage, outcomes: list[str]) -> list[dict]:
    """Build the work list from the CSV store: sha256 whose LAST try has one of the
    given `outcomes` (e.g. installed_no_alert) and that were tested offline."""
    rows = []
    for sha, r in latest_by_sha(db.results()).items():
        if r.get("outcome") not in outcomes:
            continue
        if r.get("net_online") == "1":  # keep only those analyzed offline (null/0)
            continue
        rows.append({"sha256": sha, "vt_detection_int": _int(r.get("vt_detection")),
                     "bucket": r.get("vt_bucket"), "year": r.get("catalog_year"),
                     "markets": r.get("market")})
    return rows


def process_apk(apk: Path, row: dict, sha: str, dev: Device, d, args, dirs: dict) -> tuple[dict, list, list]:
    rec = {"sha256": sha, "file_name": apk.name, "file_path": str(apk.resolve()),
           "vt_detection": row.get("vt_detection_int"), "vt_bucket": row.get("bucket"),
           "catalog_year": row.get("year"), "market": row.get("markets"),
           "net_online": 1 if is_online(dev) else 0}  # trace: analyzed online?
    rec.update(analyze(apk))
    pkg = rec.get("package")
    prefix = sha[:16]

    before = dev.third_party_packages()
    if pkg and pkg in before and not pkg.startswith(PROTECTED_PREFIXES):
        dev.uninstall(pkg)
        before.discard(pkg)

    cleanup_screen(d)
    flags = []
    if args.bypass_low_target_sdk_block and dev.sdk_int() >= 34:
        flags.append("--bypass-low-target-sdk-block")

    notif = NotificationCapture(dev).snapshot()
    log = LogcatCapture(dev, dirs["logcat"] / f"{prefix}.log", keep_full=args.full_logcat).start()
    inst = AsyncInstall(dev, apk, flags=flags, timeout=args.timeout).start()
    try:
        alerts = watch(d, inst, dirs["screenshots"], prefix, timeout=args.timeout + 10,
                       grace=args.grace, allow_scan=not args.no_scan)
        result = inst.wait(timeout=args.timeout + 15)
    finally:
        time.sleep(1)
        rec["logcat_excerpt"] = log.stop(extra_keywords=[pkg] if pkg else [])
        rec["logcat_path"] = str(dirs["logcat"] / f"{prefix}.log")

    # Play Protect notifications that appeared during the install.
    notifs = notif.collect(package=pkg)
    for n in notifs:
        n["category"] = classifier.categorize_text(" ".join(n.get("lines", [])))
        n["blocked"] = classifier.is_blocked({"title": n.get("title")})
    if notifs:
        shot = shade_screenshot(d, dev, dirs["screenshots"] / f"{prefix}_notif.png")
        if shot:
            notifs[0]["screenshot"] = shot

    for a in alerts:
        a["category"] = classifier.categorize(a)
        a["blocked"] = classifier.is_blocked(a)
    rec["install"] = result
    rec["outcome"] = classifier.outcome(alerts, result)
    rec["primary_category"] = classifier.primary_category(alerts)

    after = dev.third_party_packages()
    new = sorted(p for p in after - before if not p.startswith(PROTECTED_PREFIXES))
    rec["installed_packages"] = new
    if new and not args.keep_installed:
        rec["uninstalled"] = all(dev.uninstall(p) for p in new)

    cleanup_screen(d)
    return rec, alerts, notifs


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass
    args = parse_args()
    out = Path(args.out)
    dirs = {"screenshots": out / "screenshots", "logcat": out / "logcat", "apks": out / "apks"}
    for p in [out, *dirs.values()]:
        p.mkdir(parents=True, exist_ok=True)
    db = Storage(out)
    ui = UI()

    if args.export_only:
        for p in db.paths():
            ui.log(f"CSV: {p}")
        return 0

    try:
        apikey = read_api_key(args.apikey, DEFAULT_KEY_FILE)
        az = AndroZoo(apikey, dirs["apks"])
    except AndroZooError as e:
        ui.log(f"AndroZoo error: {e}")
        return 1

    # APK selection: outcome replay, explicit list, whole catalog, or a sample.
    if not args.sha256 and not args.catalog and not args.retest_outcomes:
        ui.log("Error: --catalog is required (except with --sha256, --retest-outcomes or --export-only).")
        return 2
    total: int | None
    if args.retest_outcomes:
        rows = retest_rows(db, args.retest_outcomes)
        total = len(rows)
        ui.log(f"Replay: {total} apps with outcome {args.retest_outcomes} will be reinstalled "
               f"(once the phone is online).")
        if not rows:
            ui.log("No app to replay for this outcome.")
            return 1
    elif args.sha256:
        rows = [{"sha256": s.lower()} for s in args.sha256]
        total = len(rows)
    elif args.all_apks:
        total = None if args.no_precount else count_catalog(args, ui)
        if total == 0:
            ui.log("No APK matches the filters.")
            return 1
        rows = catalog.stream(Path(args.catalog), args.buckets, args.max_size_mb,
                              args.year_min, args.year_max)
    else:
        rows = sample_catalog(args, ui)
        total = len(rows)
    if isinstance(rows, list) and not rows:
        ui.log("No APK selected (check the filters).")
        return 1

    # Device connection.
    try:
        dev = Device(args.serial, args.adb)
    except AdbError as e:
        ui.log(f"ADB error: {e}")
        return 1
    import uiautomator2 as u2
    ui.log(f"Connecting to {dev.serial}…")
    d = u2.connect(dev.serial)
    try:
        call_timeout(d.screen_on, UI_CALL_TIMEOUT)
    except Exception:  # noqa: BLE001
        ui.log("Warning: screen_on() did not respond (slow u2 agent?).")
    dev.stay_awake()
    if args.enable_adb_verify:
        ok = dev.put_global("verifier_verify_adb_installs", 1)
        ui.log(f"verifier_verify_adb_installs=1: {'OK' if ok else 'failed'}")
    info = dev.info()
    ui.log(f"Device: {info['manufacturer']} {info['model']} | Android "
           f"{info['android_version']} (SDK {info['sdk_int']}) | GMS {info['gms_version']}")
    if info["verifier_verify_adb_installs"] == "0":
        ui.log("WARNING: verifier_verify_adb_installs=0 — Play Protect may not scan ADB "
               "installs (--enable-adb-verify or turn on 'Verify apps over USB').")

    run_id = db.start_run(info, vars(args))
    # In replay mode we do NOT skip already-processed sha (that is the whole point).
    done = db.processed_hashes() if (args.resume and not args.retest_outcomes) else set()
    counts: dict[str, int] = {}
    tot = str(total) if total is not None else "?"
    ui.log(f"{tot} APKs to process. Results in {out.resolve()}\n")
    if done:
        ui.log(f"Resume: {len(done)} APKs already processed will be skipped.")

    ui.start(total)
    try:
        for i, row in enumerate(rows, 1):
            sha = row["sha256"].lower()
            short = sha[:12]
            if sha in done:
                ui.advance(f"[{i}/{tot}] {short} already processed")
                continue
            if args.require_online and not wait_online(dev, ui):
                ui.log("Phone offline for too long — stopping. Reconnect, then relaunch "
                       "with --resume (or --retest-outcomes).")
                break
            t0 = time.time()
            try:
                apk = az.download(sha, on_chunk=ui.download_cb())
                ui.download_done()
                if sha256_file(apk) != sha:  # guard against a corrupt cache
                    raise AndroZooError("local digest mismatch")
                rec, alerts, notifs = process_apk(apk, row, sha, dev, d, args, dirs)
            except KeyboardInterrupt:
                raise
            except AndroZooError as e:
                ui.download_done()
                rec = {"sha256": sha, "file_name": f"{sha}.apk", "file_path": "",
                       "outcome": "download_failed", "error": str(e)[:1000],
                       "vt_detection": row.get("vt_detection_int"), "vt_bucket": row.get("bucket")}
                alerts, notifs = [], []
            except Exception as e:  # noqa: BLE001
                rec = {"sha256": sha, "file_name": f"{sha}.apk", "file_path": "",
                       "outcome": "error", "error": f"{type(e).__name__}: {e}"[:1000]}
                alerts, notifs = [], []
                cleanup_screen(d)
            db.save(run_id, rec, alerts, notifs)
            done.add(sha)
            counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
            if not args.keep_apks and rec.get("file_path"):
                Path(rec["file_path"]).unlink(missing_ok=True)

            title = next((a["title"] for a in alerts if a.get("title")),
                         next((n["title"] for n in notifs if n.get("title")), ""))
            vt = rec.get("vt_detection")
            label = (f"[{i}/{tot}] {short} vt={vt} -> {rec['outcome']}"
                     f"{' | ' + title if title else ''} [{time.time() - t0:.0f}s]")
            ui.advance(label)
            ui.log(label)
            time.sleep(args.pause)
    except KeyboardInterrupt:
        ui.log("\nInterrupted. Relaunch with --resume to continue.")
    finally:
        ui.stop()
        db.end_run(run_id)
        ui.log("\nSummary: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing"))
        ui.log("CSV: " + ", ".join(str(p) for p in db.paths()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
