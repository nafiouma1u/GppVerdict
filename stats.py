#!/usr/bin/env python3
"""Summary of a GppVerdict run, in the terms of the paper: the installation
outcomes (with the failure codes), the verdicts of the blocked apps by number of
VirusTotal detections recorded in AndroZoo, the dialog titles, and the hours in
which Google Play Protect most likely did not check the installed apps. Takes the
LAST try per sha256 (a --resume run may re-append the same hash), so totals do not
double-count.

    python stats.py                    # the study's results, in output/
    python stats.py --out results_all  # another run
"""
from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from gppverdict.catalog import BUCKETS
from gppverdict.storage import latest_by_sha

# outcome -> its label in the paper's outcome table (the last two only occur with collect.py)
OUTCOMES = {
    "blocked_by_play_protect": "Blocked by Google Play Protect",
    "installed_no_alert": "Installed without alert",
    "installed_after_alert": "Installed after alert",
    "install_failed": "Installation failed",
    "timeout": "Timed out without alert",
    "timeout_after_alert": "Timed out after alert",
    "download_failed": "Download failed",
    "error": "Processing error",
}
FAILURES = {
    "INSTALL_FAILED_MISSING_SPLIT": "Missing split APKs",
    "INSTALL_FAILED_NO_MATCHING_ABIS": "No matching ABI",
    "INSTALL_FAILED_VERIFICATION_FAILURE": "Verification failure",
    "INSTALL_FAILED_DEPRECATED_SDK_VERSION": "Deprecated SDK version",
    "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED": "Malformed manifest",
    "": "No error code",
}
VERDICTS = {"old_target_sdk": "Outdated target SDK", "harmful": "Harmful", "unsafe": "Unsafe"}
ALERTED = ("blocked_by_play_protect", "installed_after_alert", "timeout_after_alert")
INSTALLABLE = ("blocked_by_play_protect", "installed_no_alert", "installed_after_alert")


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main() -> int:
    ap = argparse.ArgumentParser(description="Summary of a GppVerdict run.")
    ap.add_argument("--out", default="output",
                    help="Run directory (default: output, the study's results)")
    args = ap.parse_args()
    out = Path(args.out)
    results_csv = out / "results.csv"
    if not results_csv.exists():
        print(f"Results file not found: {results_csv}")
        return 1

    rows = list(latest_by_sha(read_csv(results_csv)).values())
    ids = {r.get("result_id") for r in rows}
    total = len(rows)

    def pct(n: int, of: int = total) -> str:
        return f"{100 * n / of:5.1f}%" if of else "     —"

    print("=" * 66)
    print(f"  SUMMARY — {args.out}")
    print("=" * 66)
    print(f"  APKs processed (distinct): {total}\n")

    # Last outcome of each APK, as in the paper's outcome table.
    outc = Counter(r.get("outcome") or "?" for r in rows)
    print("  OUTCOMES")
    for key in [*OUTCOMES, *(k for k in outc if k not in OUTCOMES)]:
        n = outc[key]
        if n or key not in ("download_failed", "error"):
            print(f"    {OUTCOMES.get(key, key):38}: {n:6}  {pct(n)}")
        if key == "install_failed":
            codes = Counter(r.get("install_failure_code") or "" for r in rows if r.get("outcome") == key)
            for code, m in codes.most_common():
                print(f"      {FAILURES.get(code, code):36}: {m:6}")

    # Verdict of each blocked app (the category of its dialog), by VirusTotal detections in AndroZoo.
    blocked = [r for r in rows if r.get("outcome") == "blocked_by_play_protect"]
    cats = Counter(r.get("primary_category") or "?" for r in blocked)
    buckets = [b[0] for b in BUCKETS] + (["n/a"] if any(not r.get("vt_bucket") for r in blocked) else [])
    print("\n  VERDICTS OF THE BLOCKED APPS, by VirusTotal detections recorded in AndroZoo")
    print(f"    {'':38}  {'apps':>6}  {'':6}" + "".join(f"{b:>7}" for b in buckets))
    for cat in [*VERDICTS, *(c for c in cats if c not in VERDICTS), None]:
        sub = blocked if cat is None else [r for r in blocked if (r.get("primary_category") or "?") == cat]
        vt = Counter(r.get("vt_bucket") or "n/a" for r in sub)
        label = "Total" if cat is None else VERDICTS.get(cat, cat)
        print(f"    {label:38}: {len(sub):6}  {pct(len(sub), len(blocked))}"
              + "".join(f"{vt[b]:7}" for b in buckets))

    # Dialogs, without the progress screens (whose "title" is the clock of the status bar).
    alerts = [a for a in read_csv(out / "alerts.csv")
              if a.get("result_id") in ids and a.get("category") != "progress"]
    alerted = sum(outc[o] for o in ALERTED)
    print("\n  ALERTS")
    print(f"    {'APKs with >=1 alert':38}: {alerted:6}  {pct(alerted)}")
    print("    By dialog title (the outdated-SDK message is titled 'Unsafe app blocked' too):")
    titles: dict[str, set] = defaultdict(set)
    for a in alerts:
        titles[a.get("title") or "?"].add(a.get("result_id"))
    for title, apps in sorted(titles.items(), key=lambda kv: -len(kv[1])):
        print(f"      {title:36}: {len(apps):6}")
    notifs = [n for n in read_csv(out / "notifications.csv") if n.get("result_id") in ids]
    with_verdict = sum(1 for n in notifs if n.get("category") in VERDICTS)
    print(f"    {'Notifications captured':38}: {len(notifs):6}  ({with_verdict} with a verdict)")

    # Hours in which Google Play Protect most likely checked nothing (paper, threats to
    # validity): among the hours with >= 20 installable apps, those whose share of blocked
    # apps fell below 3/4 of the median share.
    installable = [r for r in rows if r.get("outcome") in INSTALLABLE]
    by_hour: dict[str, list] = defaultdict(list)
    for r in installable:
        by_hour[(r.get("created_at") or "")[:13]].append(r)
    share = {h: sum(r["outcome"] == "blocked_by_play_protect" for r in v) / len(v)
             for h, v in by_hour.items() if h and len(v) >= 20}
    if share:
        median = statistics.median(share.values())
        low = sorted(h for h, s in share.items() if s < 0.75 * median)
        unchecked = sum(r["outcome"] == "installed_no_alert" for h in low for r in by_hour[h])
        span = f", {low[0]} .. {low[-1]}" if low else ""
        print("\n  UNCHECKED HOURS (block rate < 3/4 of its median, hours with >= 20 installable apps)")
        print(f"    {'Median hourly block rate':38}: {100 * median:5.1f}%  over {len(share)} hours")
        print(f"    {'Hours below 3/4 of the median':38}: {len(low):6}  "
              f"({sum(share[h] == 0 for h in low)} at 0%{span})")
        print(f"    {'Installed without alert in them':38}: {unchecked:6}  (most likely not checked)")
        print(f"    {'Blocked share of installable apps':38}: {pct(len(blocked), len(installable))}  "
              f"-> {pct(len(blocked), len(installable) - unchecked).strip()} without them")

    got_apk = total - outc["download_failed"] - outc["error"]
    print(f"\n  (check: got_apk={got_apk}, sum of outcomes={sum(outc.values())}=={total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
