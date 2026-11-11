#!/usr/bin/env python3
"""Summary of a GppVerdict run: how many APKs processed, installed,
alerted, and by alert category. Takes the LAST try per sha256 (a --resume run may
re-append the same hash), so totals do not double-count.

    python stats.py --out results_all
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from gppverdict.storage import latest_by_sha

INSTALLED = ("installed_no_alert", "installed_after_alert")
ALERTED = ("blocked_by_play_protect", "installed_after_alert", "timeout_after_alert")


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main() -> int:
    ap = argparse.ArgumentParser(description="Summary of a GppVerdict run.")
    ap.add_argument("--out", default="results_all", help="Run directory (default: results_all)")
    args = ap.parse_args()
    out = Path(args.out)
    results_csv = out / "results.csv"
    if not results_csv.exists():
        print(f"Results file not found: {results_csv}")
        return 1

    latest = latest_by_sha(read_csv(results_csv))
    latest_ids = {r.get("result_id") for r in latest.values()}
    total = len(latest)

    def pct(n):
        return f"{100 * n / total:.1f}%" if total else "—"

    print("=" * 58)
    print(f"  SUMMARY — {args.out}")
    print("=" * 58)
    print(f"  APKs processed (distinct): {total}\n")

    # Install funnel (last state of each APK).
    outc = Counter(r.get("outcome") for r in latest.values())
    installed = sum(outc.get(o, 0) for o in INSTALLED)
    alerted = sum(1 for r in latest.values() if r.get("outcome") in ALERTED)
    got_apk = total - outc.get("download_failed", 0) - outc.get("error", 0)

    print("  INSTALLATION")
    rows = [
        ("Installed (then uninstalled)", installed),
        ("Blocked by Play Protect", outc.get("blocked_by_play_protect", 0)),
        ("Install failed (no alert)", outc.get("install_failed", 0)),
        ("Download failed", outc.get("download_failed", 0)),
        ("Processing error", outc.get("error", 0)),
        ("Timeout (with / after alert)", outc.get("timeout", 0) + outc.get("timeout_after_alert", 0)),
    ]
    for label, n in rows:
        print(f"    {label:38}: {n:5}  ({pct(n)})")

    print("\n  ALERTS")
    print(f"    APKs with >=1 alert                   : {alerted:5}  ({pct(alerted)})")

    alerts = [a for a in read_csv(out / "alerts.csv") if a.get("result_id") in latest_ids]

    def by(field):
        counts: dict[str, set] = {}
        for a in alerts:
            counts.setdefault(a.get(field) or "?", set()).add(a.get("result_id"))
        return sorted(((k, len(v)) for k, v in counts.items()), key=lambda x: -x[1])

    print("    By type (dialog title):")
    for title, n in by("title"):
        print(f"      {title:38}: {n:5}")
    print("    By category (classifier):")
    for cat, n in by("category"):
        print(f"      {cat:38}: {n:5}")

    notifs = [n for n in read_csv(out / "notifications.csv") if n.get("result_id") in latest_ids]
    print(f"\n  Play Protect notifications captured       : {len(notifs)}")

    print(f"\n  (check: got_apk={got_apk}, sum of outcomes={sum(outc.values())}=={total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
