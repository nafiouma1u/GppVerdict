#!/usr/bin/env python3
"""GppVerdict

Installs the APKs from a local folder one by one onto a USB-connected phone,
captures Google Play Protect alerts (text + screenshot + logcat) and stores
everything to CSV.

Example:
    python run.py --apks /path/to/apks --out results
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from gppverdict import classifier
from gppverdict.device import AdbError, Device
from gppverdict.installer import AsyncInstall
from gppverdict.logcat import LogcatCapture
from gppverdict.static import analyze, sha256_file
from gppverdict.storage import Storage
from gppverdict.watcher import watch

PROTECTED_PREFIXES = ("com.github.uiautomator",)  # uiautomator2 agent: never uninstall


def parse_args():
    p = argparse.ArgumentParser(description="Automatic capture of Google Play Protect alerts.")
    p.add_argument("--apks", help="Folder containing the .apk files (on the PC)")
    p.add_argument("--out", default="results", help="Output directory (default: results)")
    p.add_argument("--serial", help="ADB serial number (if several devices)")
    p.add_argument("--adb", default="adb", help="Path to adb if not on PATH")
    p.add_argument("--recursive", action="store_true", help="Look for APKs in subfolders")
    p.add_argument("--limit", type=int, help="Process only the first N APKs (test)")
    p.add_argument("--resume", action="store_true", help="Skip APKs already processed (same sha256)")
    p.add_argument("--timeout", type=int, default=150, help="Per-APK timeout in seconds (default: 150)")
    p.add_argument("--grace", type=float, default=4.0,
                   help="Seconds to keep watching after the install ends (default: 4)")
    p.add_argument("--pause", type=float, default=2.0, help="Pause between APKs (default: 2s)")
    p.add_argument("--no-scan", action="store_true",
                   help="Do not accept sending the APK to Google for analysis")
    p.add_argument("--bypass-low-target-sdk-block", action="store_true",
                   help="Android 14+: bypass the system block of apps with targetSdk < 23")
    p.add_argument("--keep-installed", action="store_true", help="Do not uninstall after the test")
    p.add_argument("--full-logcat", action="store_true", help="Also keep the full logcat")
    p.add_argument("--enable-adb-verify", action="store_true",
                   help="Try to enable verifier_verify_adb_installs=1")
    p.add_argument("--export-only", action="store_true",
                   help="Print where the CSV files are and exit (the CSVs are the store)")
    return p.parse_args()


def collect_apks(folder: Path, recursive: bool) -> list[Path]:
    pattern = "**/*" if recursive else "*"
    return sorted(p for p in folder.glob(pattern) if p.is_file() and p.suffix.lower() == ".apk")


def cleanup_screen(d) -> None:
    try:
        d.press("back")
        d.press("home")
    except Exception:  # noqa: BLE001
        pass


def process_apk(apk: Path, sha: str, dev: Device, d, args, dirs: dict) -> tuple[dict, list[dict]]:
    rec = {"sha256": sha, "file_name": apk.name, "file_path": str(apk.resolve())}
    rec.update(analyze(apk))
    pkg = rec.get("package")
    prefix = sha[:16]

    # Clean state: uninstall any version already present.
    before = dev.third_party_packages()
    if pkg and pkg in before and not pkg.startswith(PROTECTED_PREFIXES):
        dev.uninstall(pkg)
        before.discard(pkg)

    cleanup_screen(d)
    flags = []
    if args.bypass_low_target_sdk_block and dev.sdk_int() >= 34:
        flags.append("--bypass-low-target-sdk-block")

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

    for a in alerts:
        a["category"] = classifier.categorize(a)
        a["blocked"] = classifier.is_blocked(a)
    rec["install"] = result
    rec["outcome"] = classifier.outcome(alerts, result)
    rec["primary_category"] = classifier.primary_category(alerts)

    # What was actually installed (diff of the package list).
    after = dev.third_party_packages()
    new = sorted(p for p in after - before if not p.startswith(PROTECTED_PREFIXES))
    rec["installed_packages"] = new
    if new and not args.keep_installed:
        rec["uninstalled"] = all(dev.uninstall(p) for p in new)

    cleanup_screen(d)
    return rec, alerts


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # Windows console + Cyrillic names
    except Exception:  # noqa: BLE001
        pass
    args = parse_args()
    out = Path(args.out)
    dirs = {"screenshots": out / "screenshots", "logcat": out / "logcat"}
    for p in [out, *dirs.values()]:
        p.mkdir(parents=True, exist_ok=True)
    db = Storage(out)

    if args.export_only:
        for p in db.paths():
            print(f"CSV: {p}")
        return 0
    if not args.apks:
        print("Error: --apks is required.")
        return 2

    apks = collect_apks(Path(args.apks), args.recursive)
    if args.limit:
        apks = apks[: args.limit]
    if not apks:
        print(f"No .apk found in {args.apks}")
        return 1

    try:
        dev = Device(args.serial, args.adb)
    except AdbError as e:
        print(f"ADB error: {e}")
        return 1

    import uiautomator2 as u2  # late import: --help works without a phone

    print(f"Connecting to {dev.serial}…")
    d = u2.connect(dev.serial)
    d.screen_on()
    dev.stay_awake()

    if args.enable_adb_verify:
        ok = dev.put_global("verifier_verify_adb_installs", 1)
        print(f"verifier_verify_adb_installs=1: {'OK' if ok else 'failed (enable it manually)'}")
    info = dev.info()
    print(f"Device: {info['manufacturer']} {info['model']} | Android {info['android_version']} "
          f"(SDK {info['sdk_int']}) | GMS {info['gms_version']}")
    if info["verifier_verify_adb_installs"] == "0":
        print("WARNING: verifier_verify_adb_installs=0, Play Protect may not scan ADB installs. "
              "Turn on 'Verify apps over USB' or relaunch with --enable-adb-verify.")

    run_id = db.start_run(info, vars(args))
    done = db.processed_hashes() if args.resume else set()
    counts: dict[str, int] = {}
    print(f"{len(apks)} APKs to process. Results in {out.resolve()}\n")

    try:
        for i, apk in enumerate(apks, 1):
            sha = sha256_file(apk)
            if sha in done:
                print(f"[{i}/{len(apks)}] {apk.name}: already processed, skipped")
                continue
            t0 = time.time()
            try:
                rec, alerts = process_apk(apk, sha, dev, d, args, dirs)
            except KeyboardInterrupt:
                raise
            except Exception as e:  # noqa: BLE001
                rec = {"sha256": sha, "file_name": apk.name, "file_path": str(apk.resolve()),
                       "outcome": "error", "error": f"{type(e).__name__}: {e}"[:1000]}
                alerts = []
                cleanup_screen(d)
            db.save(run_id, rec, alerts)
            done.add(sha)
            counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
            title = next((a["title"] for a in alerts if a.get("title")), "")
            print(f"[{i}/{len(apks)}] {apk.name} -> {rec['outcome']}"
                  f"{' (' + rec['primary_category'] + ')' if rec.get('primary_category') else ''}"
                  f"{' | ' + title if title else ''} [{time.time() - t0:.1f}s]")
            time.sleep(args.pause)
    except KeyboardInterrupt:
        print("\nInterrupted. Relaunch with --resume to continue.")
    finally:
        db.end_run(run_id)
        print("\nSummary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing")
        print("CSV:", ", ".join(str(p) for p in db.paths()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
