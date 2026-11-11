#!/usr/bin/env python3
"""GppVerdict — reinstall APKs already flagged by Play Protect and watch
the reaction.

A special mode, deliberately separate from collect.py (whose rule is to NEVER force
the install of a flagged app). Here we DELIBERATELY reinstall the APKs Play Protect
blocked (categories harmful / unsafe) to observe what it does once the app is present
on the device: a "Harmful app found" notification, automatic removal of the app, etc.

Important points:

- The tool CHANGES NO protection setting. YOU configure the phone (Play Protect /
  "Verify apps over USB"). For `adb install` to succeed, "Verify apps over USB" must be
  DISABLED: otherwise Play Protect blocks the install (which is exactly what produced
  the alerts we already have). Once the app is installed, Play Protect detects it during
  its background scan and posts the notification — you can trigger it manually in Play
  Store → profile → Play Protect → Scan if nothing appears.
- After a successful install, the app STAYS in place and we watch Play Protect
  notifications for --observe seconds (default 300 = 5 min). At the end of the window, if
  the app is still there, we uninstall it (unless --keep-installed). If Play Protect
  removes it first, we record that.

A DEDICATED phone is mandatory: real malware is installed here, with no SIM and no
personal account, and resettable.

Examples:
    # The harmful/unsafe apps already found in results_all
    python install_flagged.py

    # Specific hashes, 10-minute window, keep the app installed
    python install_flagged.py --sha256 f828c1e2... 73704fc3... --observe 600 --keep-installed
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from gppverdict import classifier
from gppverdict.androzoo import AndroZoo, AndroZooError, read_api_key
from gppverdict.device import AdbError, Device
from gppverdict.installer import AsyncInstall
from gppverdict.notifications import NotificationCapture
from gppverdict.static import analyze, sha256_file
from gppverdict.storage import Storage, latest_by_sha

PROTECTED_PREFIXES = ("com.github.uiautomator",)
DEFAULT_KEY_FILE = Path(__file__).resolve().parent / ".androzoo_key"


def parse_args():
    p = argparse.ArgumentParser(
        description="Reinstall APKs flagged by Play Protect and observe its reaction.")
    p.add_argument("--out", default="results_flagged",
                   help="Output directory (new CSVs + screenshots). Default: results_flagged")
    p.add_argument("--source", default="results_all",
                   help="Run directory to read the flagged sha256 from (default: results_all)")
    p.add_argument("--categories", nargs="+", default=None,
                   help="Alert categories to reinstall (default: ALL, e.g. harmful unsafe "
                        "old_target_sdk). Without this flag, every app that got an alert.")
    p.add_argument("--sha256", nargs="+",
                   help="Reinstall these exact sha256 instead of reading the run directory")
    p.add_argument("--apikey", help="AndroZoo API key (otherwise read from .androzoo_key)")
    p.add_argument("--serial", help="ADB serial number (if several devices)")
    p.add_argument("--adb", default="adb", help="Path to adb if not on PATH")
    p.add_argument("--resume", action="store_true",
                   help="Skip sha256 already processed in the output directory (restartable run).")
    p.add_argument("--install-timeout", type=int, default=180,
                   help="Install timeout in seconds (default: 180)")
    p.add_argument("--observe", type=float, default=300.0,
                   help="Observation window after install, in seconds (default: 300 = 5 min)")
    p.add_argument("--poll", type=float, default=5.0,
                   help="Interval between two notification reads (default: 5s)")
    p.add_argument("--keep-installed", action="store_true",
                   help="Do not uninstall at the end of the window (the app stays on the phone)")
    p.add_argument("--keep-apks", action="store_true", help="Keep the downloaded APKs (cache)")
    p.add_argument("--pause", type=float, default=3.0, help="Pause between APKs (default: 3s)")
    return p.parse_args()


def log(msg: str) -> None:
    print(msg, flush=True)


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def flagged_from_csv(source: Path, categories: list[str] | None) -> list[dict]:
    """Read the (unique) sha256 that got an alert, from a run's CSV files.

    `categories=None`: every app that got an alert (any category). Otherwise, only
    those with an alert in `categories`."""
    results_csv, alerts_csv = source / "results.csv", source / "alerts.csv"
    if not results_csv.exists():
        raise FileNotFoundError(f"Results file not found: {results_csv}")
    with open(results_csv, newline="", encoding="utf-8-sig") as f:
        res = latest_by_sha(list(csv.DictReader(f)))
    cats_by_sha: dict[str, list[str]] = {}
    order: list[str] = []
    if alerts_csv.exists():
        with open(alerts_csv, newline="", encoding="utf-8-sig") as f:
            for a in csv.DictReader(f):
                cat, sha = a.get("category"), a.get("sha256")
                if not sha or (categories and cat not in categories):
                    continue
                if sha not in cats_by_sha:
                    cats_by_sha[sha] = []
                    order.append(sha)
                if cat and cat not in cats_by_sha[sha]:
                    cats_by_sha[sha].append(cat)
    out = []
    for sha in order:
        r = res.get(sha, {})
        out.append({"sha256": sha, "package": r.get("package"),
                    "vt_detection_int": _int(r.get("vt_detection")), "bucket": r.get("vt_bucket"),
                    "year": r.get("catalog_year"), "flagged_as": ",".join(cats_by_sha[sha])})
    return out


def shade_screenshot(d, dev, path: Path) -> str | None:
    """Open the notification shade, screenshot it, then collapse it."""
    try:
        dev.shell("cmd statusbar expand-notifications")
        time.sleep(1.0)
        d.screenshot(str(path))
        return str(path)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            dev.shell("cmd statusbar collapse")
        except Exception:  # noqa: BLE001
            pass


def observe(d, dev, notif: NotificationCapture, pkg: str | None, prefix: str,
            shots_dir: Path, duration: float, poll: float) -> tuple[list[dict], bool]:
    """Watch Play Protect notifications and app removal for `duration` seconds.

    Returns (captured notifications, app_removed_by_play_protect)."""
    captured: dict[str, dict] = {}
    removed = False
    end = time.time() + duration
    while time.time() < end:
        time.sleep(poll)
        try:
            fresh = notif.collect(package=pkg)
        except Exception:  # noqa: BLE001
            fresh = []
        for n in fresh:
            key = n.get("key") or f"{n.get('pkg')}:{n.get('title')}:{n.get('when')}"
            if key in captured:
                continue
            n["category"] = classifier.categorize_text(" ".join(n.get("lines", [])))
            n["blocked"] = classifier.is_blocked({"title": n.get("title")})
            shot = shade_screenshot(d, dev, shots_dir / f"{prefix}_notif_{len(captured) + 1}.png")
            if shot:
                n["screenshot"] = shot
            captured[key] = n
            tag = "BLOCKED" if n["blocked"] else n["category"]
            log(f"    🔔 Play Protect notif [{tag}]: {n.get('title')} — {n.get('text') or ''}")
        if pkg:
            try:
                if pkg not in dev.third_party_packages():
                    removed = True
                    log("    🗑  Play Protect removed the application.")
                    break
            except Exception:  # noqa: BLE001
                pass
        remaining = int(end - time.time())
        if remaining > 0 and remaining % 30 == 0:
            log(f"    …observing, {remaining}s left "
                f"({len(captured)} notif, app {'absent' if removed else 'present'})")
    return list(captured.values()), removed


def process(sha: str, meta: dict, az: AndroZoo, dev: Device, d, args, dirs: dict) -> tuple[dict, list]:
    prefix = sha[:16]
    rec = {"sha256": sha, "file_name": f"{sha}.apk", "file_path": "",
           "vt_detection": meta.get("vt_detection_int"), "vt_bucket": meta.get("bucket"),
           "catalog_year": meta.get("year"),
           "market": f"flagged_as={meta.get('flagged_as')}"}

    apk = az.download(sha)
    rec["file_path"] = str(apk.resolve())
    if sha256_file(apk) != sha:
        raise AndroZooError("local digest mismatch (corrupt cache?)")
    rec.update(analyze(apk))
    pkg = rec.get("package") or meta.get("package")
    log(f"  package: {pkg or '?'}  (targetSdk={rec.get('target_sdk')}, "
        f"vt={rec.get('vt_detection')}, flagged={meta.get('flagged_as')})")

    # Clean starting point: remove any version already present.
    before = dev.third_party_packages()
    if pkg and pkg in before and not pkg.startswith(PROTECTED_PREFIXES):
        dev.uninstall(pkg)

    notif = NotificationCapture(dev).snapshot()
    log("  installing (adb install)…")
    inst = AsyncInstall(dev, apk, timeout=args.install_timeout).start()
    result = inst.wait(timeout=args.install_timeout + 15) or {}
    rec["install"] = result
    notifs: list[dict] = []

    if not result.get("success"):
        code = result.get("failure_code")
        rec["outcome"] = "install_blocked" if code else (
            "install_timeout" if result.get("timed_out") else "install_failed")
        rec["installed_packages"] = []
        log(f"  install failed: {code or result.get('output', '')[:200]}")
        if code:
            log("  → Check that 'Verify apps over USB' is DISABLED on the phone "
                "(otherwise Play Protect blocks the install).")
        # Even when blocked, a notification may have appeared: keep it.
        try:
            for n in notif.collect(package=pkg):
                n["category"] = classifier.categorize_text(" ".join(n.get("lines", [])))
                n["blocked"] = classifier.is_blocked({"title": n.get("title")})
                notifs.append(n)
        except Exception:  # noqa: BLE001
            pass
        return rec, notifs

    log(f"  install OK in {result.get('duration_s')}s — observing {args.observe:.0f}s "
        f"(the app stays in place)…")
    notifs, removed = observe(d, dev, notif, pkg, prefix, dirs["screenshots"],
                              args.observe, args.poll)

    still_here = bool(pkg) and pkg in dev.third_party_packages()
    if removed:
        rec["outcome"] = "removed_by_play_protect"
    elif notifs and still_here:
        rec["outcome"] = "notified_still_installed"
    elif notifs:
        rec["outcome"] = "notified_removed"
    else:
        rec["outcome"] = "installed_no_reaction"

    # Cleanup: at the end of the window, if the app is still there, uninstall it.
    rec["installed_packages"] = [pkg] if still_here else []
    if still_here and not args.keep_installed:
        rec["uninstalled"] = dev.uninstall(pkg)
        log(f"  uninstall: {'OK' if rec['uninstalled'] else 'failed'}")
    elif still_here:
        log("  app kept on the phone (--keep-installed).")

    rec["primary_category"] = next((n["category"] for n in notifs if n.get("category")), None)
    return rec, notifs


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass
    args = parse_args()
    out = Path(args.out)
    dirs = {"screenshots": out / "screenshots", "apks": out / "apks"}
    for p in [out, *dirs.values()]:
        p.mkdir(parents=True, exist_ok=True)

    # List of APKs to reinstall.
    if args.sha256:
        targets = [{"sha256": s.lower()} for s in args.sha256]
    else:
        try:
            targets = flagged_from_csv(Path(args.source), args.categories)
        except FileNotFoundError as e:
            log(f"Error: {e}")
            return 2
    if not targets:
        log("No flagged APK to reinstall (check --source / --categories / --sha256).")
        return 1

    try:
        az = AndroZoo(read_api_key(args.apikey, DEFAULT_KEY_FILE), dirs["apks"])
    except AndroZooError as e:
        log(f"AndroZoo error: {e}")
        return 1
    try:
        dev = Device(args.serial, args.adb)
    except AdbError as e:
        log(f"ADB error: {e}")
        return 1

    import uiautomator2 as u2
    log(f"Connecting to {dev.serial}…")
    d = u2.connect(dev.serial)
    try:
        d.screen_on()
    except Exception:  # noqa: BLE001
        pass
    dev.stay_awake()
    info = dev.info()
    log(f"Device: {info['manufacturer']} {info['model']} | Android "
        f"{info['android_version']} (SDK {info['sdk_int']}) | GMS {info['gms_version']}")
    verify = info["verifier_verify_adb_installs"]
    log(f"verifier_verify_adb_installs = {verify}  (package_verifier_enable = "
        f"{info['package_verifier_enable']})")
    if verify == "1":
        log("WARNING: 'Verify apps over USB' is ENABLED → Play Protect will BLOCK these "
            "installs. Disable it on the phone so the install succeeds, then relaunch.")

    db = Storage(out)
    run_id = db.start_run(info, vars(args))
    done = db.processed_hashes() if args.resume else set()
    counts: dict[str, int] = {}
    log(f"\n{len(targets)} flagged APKs to reinstall. Output: {out.resolve()}")
    if done:
        log(f"Resume: {len(done)} APKs already processed will be skipped.")
    log("⚠️  Real malware will be installed. Dedicated phone only.\n")

    try:
        for i, meta in enumerate(targets, 1):
            sha = meta["sha256"].lower()
            if sha in done:
                log(f"[{i}/{len(targets)}] {sha[:16]} already processed — skipped")
                continue
            log(f"[{i}/{len(targets)}] {sha[:16]}")
            t0 = time.time()
            try:
                rec, notifs = process(sha, meta, az, dev, d, args, dirs)
            except KeyboardInterrupt:
                raise
            except AndroZooError as e:
                rec = {"sha256": sha, "file_name": f"{sha}.apk", "file_path": "",
                       "outcome": "download_failed", "error": str(e)[:1000]}
                notifs = []
                log(f"  download failed: {e}")
            except Exception as e:  # noqa: BLE001
                rec = {"sha256": sha, "file_name": f"{sha}.apk", "file_path": "",
                       "outcome": "error", "error": f"{type(e).__name__}: {e}"[:1000]}
                notifs = []
                log(f"  error: {type(e).__name__}: {e}")
            db.save(run_id, rec, [], notifs)
            counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
            if not args.keep_apks and rec.get("file_path"):
                Path(rec["file_path"]).unlink(missing_ok=True)
            log(f"  → {rec['outcome']}  ({len(notifs)} notif, {time.time() - t0:.0f}s)\n")
            time.sleep(args.pause)
    except KeyboardInterrupt:
        log("\nInterrupted.")
    finally:
        db.end_run(run_id)
        log("Summary: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing"))
        log("CSV: " + ", ".join(str(p) for p in db.paths()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
