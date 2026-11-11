#!/usr/bin/env python3
"""
vt_lookup.py — VirusTotal lookup for a folder of APKs, by SHA-256.

Hashes every *.apk in --apks, fetches each file's VirusTotal report
(GET /api/v3/files/<sha256>, which works with a free public-API key), caches
each raw response under vt_out/, and writes a summary table to
vt_apks_summary.csv. If the folder has a manifest.csv (as the
harmful_unsafe_apks dataset does), its package, label, Play Protect category,
year and vt_detection columns are merged in, so VirusTotal's report sits next to
the AndroZoo catalog's detection count. Counts come from each file's *last* VT
analysis (see vt_last_analysis); nothing is uploaded or re-scanned.

Cached reports are reused on re-run (so you never re-spend API quota); pass
--refresh to re-query. Only definitive answers are cached: a report, or "not on
VT". Quota (HTTP 429) and network errors are retried; if they persist (e.g. the
free tier's daily quota is used up) or on Ctrl+C, the run stops, still writes
the summary (APKs not yet queried show as "pending"), and re-running the same
command picks up where it left off. The API key is read from the VT_KEY
environment variable, else from a .vt_key file next to this script, and is only
required if something actually needs querying.

  export VT_KEY=xxxxxxxx
  python3 vt_lookup.py --apks path/to/harmful_unsafe_apks

The free tier allows 4 lookups/min: each 429 is simply waited out (~1 min per
4 APKs); or pass --sleep 15 to pace requests instead.

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FILES_URL = "https://www.virustotal.com/api/v3/files/"
KEY_FILE = Path(__file__).resolve().parent / ".vt_key"
TRIES = 3        # attempts per APK on 429 / 5xx / network errors
QUOTA_WAIT = 61  # seconds; the free tier's 4-lookup budget is per minute

COLS = ["sha256", "apk_file", "package", "app_label", "primary_category", "catalog_year",
        "az_vt_detection", "vt_status", "vt_malicious", "vt_suspicious", "vt_engines",
        "vt_threat_label", "vt_last_analysis", "vt_first_submission"]


class StopRun(Exception):
    """An error every remaining request would hit too (bad key, quota, network)."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_key() -> str:
    key = os.environ.get("VT_KEY", "").strip()
    if not key and KEY_FILE.is_file():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    return key


def vt_get(sha256: str, key: str, timeout: int = 30) -> tuple[int, dict]:
    """GET one file report -> (HTTP status, JSON body); status 0 = network error."""
    req = urllib.request.Request(FILES_URL + sha256, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)  # VT returns JSON error objects
        except json.JSONDecodeError:
            return exc.code, {"error": {"code": f"HTTP{exc.code}", "message": body[:200]}}
    except Exception as exc:  # noqa: BLE001  (URLError, timeout, SSL, bad JSON)
        return 0, {"error": {"code": "network", "message": str(exc)}}


def error_code(vt: dict) -> str:
    return vt.get("error", {}).get("code", "")


def lookup(sha256: str, key: str) -> dict:
    """One file report, retrying quota/transient errors; StopRun if they persist."""
    for attempt in range(1, TRIES + 1):
        status, vt = vt_get(sha256, key)
        if status in (401, 403):
            raise StopRun(f"API key rejected ({error_code(vt)}, HTTP {status})")
        if status not in (0, 429) and status < 500:
            return vt  # a report, NotFoundError, or some other per-file error
        err = f"{error_code(vt)}: {vt.get('error', {}).get('message', '')}"[:200]
        if attempt == TRIES:
            raise StopRun(f"{err} (still failing after {TRIES} tries)")
        wait = QUOTA_WAIT if status == 429 else 10 * attempt
        print(f"    {err} — retrying in {wait}s")
        time.sleep(wait)


def iso_date(ts) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else ""


def summarize(vt: dict | None) -> dict:
    """Reduce a VT file report (or error; None = not queried) to the summary columns."""
    out = {"package": "", "vt_status": "pending", "vt_malicious": "", "vt_suspicious": "",
           "vt_engines": "", "vt_threat_label": "", "vt_last_analysis": "",
           "vt_first_submission": ""}
    if vt is None:
        return out
    if "data" not in vt:
        code = error_code(vt) or "unknown"
        out["vt_status"] = "not_found" if code == "NotFoundError" else f"error:{code}"
        return out
    a = vt["data"].get("attributes", {})
    st = a.get("last_analysis_stats", {})
    out.update({
        "package": a.get("androguard", {}).get("Package", ""),
        "vt_status": "found",
        "vt_malicious": st.get("malicious", 0),
        "vt_suspicious": st.get("suspicious", 0),
        # engines that gave a verdict (excludes type-unsupported / timeout / failure)
        "vt_engines": sum(st.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless")),
        "vt_threat_label": a.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        "vt_last_analysis": iso_date(a.get("last_analysis_date")),
        "vt_first_submission": iso_date(a.get("first_submission_date")),
    })
    return out


def load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # missing, or cut short by an interrupted write
        return None


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--apks", type=Path, required=True, help="folder containing the .apk files")
    p.add_argument("--manifest", type=Path,
                   help="CSV with a sha256 column to merge in (default: <apks>/manifest.csv if present)")
    p.add_argument("--cache-dir", type=Path, default=Path("vt_out"), help="dir for raw VT responses")
    p.add_argument("--out", default="vt_apks_summary.csv", help="summary CSV path")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="seconds between API calls (free tier = 4/min, so 15; 429s are waited out anyway)")
    p.add_argument("--refresh", action="store_true", help="re-query even if cached")
    p.add_argument("--limit", type=int, default=None, help="only process the first N APKs (by name)")
    args = p.parse_args()

    folder = args.apks.expanduser()
    if not folder.is_dir():
        sys.exit(f"not a folder: {folder}")
    apks = sorted(f for f in folder.iterdir() if f.is_file() and f.suffix.lower() == ".apk")
    apks = apks[: args.limit]
    if not apks:
        sys.exit(f"no .apk files in {folder}")

    manifest: dict[str, dict] = {}
    mpath = (args.manifest or folder / "manifest.csv").expanduser()
    if mpath.is_file():
        with open(mpath, newline="", encoding="utf-8") as fh:
            manifest = {r.get("sha256", "").strip().lower(): r for r in csv.DictReader(fh)}
    elif args.manifest:
        sys.exit(f"manifest not found: {mpath}")

    print(f"hashing {len(apks)} APK(s) in {folder} ...")
    files: dict[str, Path] = {}
    for f in apks:
        sha = sha256_file(f)
        if re.fullmatch(r"[0-9a-fA-F]{64}", f.stem) and f.stem.lower() != sha:
            print(f"  warning: {f.name} is named by a hash, but its content hashes to {sha}")
        files.setdefault(sha, f)

    args.cache_dir.mkdir(parents=True, exist_ok=True)

    def cache_path(sha: str) -> Path:
        return args.cache_dir / f"{sha}.json"

    results = {sha: None if args.refresh else load_json(cache_path(sha)) for sha in files}
    todo = [sha for sha, vt in results.items() if vt is None]
    stopped = ""
    if todo:
        key = read_key()
        if not key:
            sys.exit(f"{len(todo)} APK(s) not cached and no API key: "
                     f"`export VT_KEY=...` or put the key in {KEY_FILE}")
        print(f"querying VirusTotal for {len(todo)} APK(s) ({len(files) - len(todo)} cached)")
        try:
            for i, sha in enumerate(todo, 1):
                if i > 1 and args.sleep:
                    time.sleep(args.sleep)
                vt = lookup(sha, key)
                results[sha] = vt
                if "data" in vt or error_code(vt) == "NotFoundError":  # definitive: cache it
                    cache_path(sha).write_text(json.dumps(vt, ensure_ascii=False, indent=2),
                                               encoding="utf-8")
                s = summarize(vt)
                detail = f"  {s['vt_malicious']}/{s['vt_engines']}" if s["vt_status"] == "found" else ""
                print(f"[vt] {i}/{len(todo)} {sha[:12]}  {s['vt_status']}{detail}")
        except StopRun as exc:
            stopped = str(exc)
        except KeyboardInterrupt:
            stopped = "interrupted"

    # One row per APK: VT summary + the manifest's columns (manifest package wins).
    rows = []
    for sha, f in files.items():
        row = summarize(results[sha])
        m = manifest.get(sha, {})
        row.update(sha256=sha, apk_file=f.name, package=m.get("package") or row["package"],
                   app_label=m.get("app_label", ""), primary_category=m.get("primary_category", ""),
                   catalog_year=m.get("catalog_year", ""), az_vt_detection=m.get("vt_detection", ""))
        rows.append(row)

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)

    print(f"\n{'sha256':12}  {'package':40}  {'category':8}  {'az_vt':>5}  {'vt_status':10}  "
          f"{'mal/eng':>7}  last_scan")
    print("-" * 104)
    for r in rows:
        mal = f"{r['vt_malicious']}/{r['vt_engines']}" if r["vt_status"] == "found" else ""
        print(f"{r['sha256'][:12]}  {r['package'][:40]:40}  {r['primary_category']:8}  "
              f"{r['az_vt_detection']:>5}  {r['vt_status']:10}  {mal:>7}  {r['vt_last_analysis']}")

    counts = Counter(r["vt_status"] for r in rows)
    print(f"\n{len(rows)} APK(s): " + ", ".join(f"{n} {s}" for s, n in counts.most_common()))
    found = [r for r in rows if r["vt_status"] == "found"]
    if found:
        line = (f"VT malicious >= 1: {sum(r['vt_malicious'] > 0 for r in found)}/{len(found)}"
                " at last VT scan")
        cat = [r for r in found if str(r["az_vt_detection"]).isdigit()]
        if cat:
            line += (" (catalog vt_detection >= 1: "
                     f"{sum(int(r['az_vt_detection']) > 0 for r in cat)}/{len(cat)})")
        print(line)
    print(f"summary -> {args.out}  (raw responses in {args.cache_dir}/)")
    if stopped:
        pending = sum(r["vt_status"] == "pending" for r in rows)
        sys.exit(f"stopped early: {stopped}\n{pending} APK(s) still pending: "
                 "re-run the same command to continue (cached ones are skipped)")


if __name__ == "__main__":
    main()
