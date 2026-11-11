#!/usr/bin/env python3
"""
harmful_vs_vt.py — final table of the apps Play Protect flagged (harmful /
unsafe), with their VirusTotal verdicts.

One row per app: Play Protect's verdict and dialog text (the run's results.csv
+ alerts.csv, last try per sha256), the AndroZoo catalog's VT detection count,
and the VT report that vt_lookup.py cached in vt_out/<sha256>.json. Both VT
counts are bucketed with the study's thresholds (vt0, vt1-4, vt5-14, vt15+).
VT figures date from each file's last VT analysis (vt_last_analysis), not from
the Play Protect test (pp_test_date).

    python3 harmful_vs_vt.py        # output/ + vt_out/ -> report/harmful_vs_vt.csv
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from gppverdict.catalog import BUCKETS, bucket_of
from gppverdict.storage import latest_by_sha
from vt_lookup import load_json, summarize

FLAGGED = ("harmful", "unsafe")
COLS = ["sha256", "package", "app_label", "catalog_year", "target_sdk",
        "pp_verdict", "pp_alert_title", "pp_alert_body", "outcome", "pp_test_date",
        "az_vt_detection", "az_vt_bucket",
        "vt_status", "vt_malicious", "vt_suspicious", "vt_engines", "vt_bucket",
        "vt_threat_label", "vt_detections", "vt_last_analysis", "vt_first_submission"]


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def detections(vt: dict | None) -> str:
    """'Engine=label; ...' for the engines that flag the file as malicious."""
    res = (vt or {}).get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    return "; ".join(f"{eng}={d.get('result')}" for eng, d in sorted(res.items())
                     if d.get("category") == "malicious")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, default=Path("output"),
                    help="run directory with results.csv + alerts.csv (default: output)")
    ap.add_argument("--vt-dir", type=Path, default=Path("vt_out"),
                    help="VT reports cached by vt_lookup.py (default: vt_out)")
    ap.add_argument("--out", type=Path, default=Path("report/harmful_vs_vt.csv"),
                    help="CSV to write (default: report/harmful_vs_vt.csv)")
    args = ap.parse_args()

    results = [r for r in latest_by_sha(read_csv(args.run / "results.csv")).values()
               if r.get("primary_category") in FLAGGED]
    alerts = {}  # result_id -> its harmful/unsafe dialog
    for a in read_csv(args.run / "alerts.csv"):
        if a.get("category") in FLAGGED:
            alerts.setdefault(a.get("result_id"), a)

    rows = []
    for r in results:
        vt = load_json(args.vt_dir / f"{r['sha256']}.json")
        s = summarize(vt)
        alert = alerts.get(r.get("result_id"), {})
        rows.append({
            "sha256": r["sha256"], "package": r.get("package"), "app_label": r.get("app_label"),
            "catalog_year": r.get("catalog_year"), "target_sdk": r.get("target_sdk"),
            "pp_verdict": r["primary_category"], "pp_alert_title": alert.get("title"),
            "pp_alert_body": alert.get("body"), "outcome": r.get("outcome"),
            "pp_test_date": (r.get("created_at") or "")[:10],
            "az_vt_detection": r.get("vt_detection"), "az_vt_bucket": r.get("vt_bucket"),
            **{k: v for k, v in s.items() if k.startswith("vt_")},
            "vt_bucket": bucket_of(s["vt_malicious"]) if s["vt_status"] == "found" else "",
            "vt_detections": detections(vt),
        })
    rows.sort(key=lambda x: (FLAGGED.index(x["pp_verdict"]), x["catalog_year"] or "",
                             (x["package"] or "").lower()))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)

    print(f"{len(rows)} flagged apps -> {args.out}\n")
    names = [b[0] for b in BUCKETS]
    print(f"{'pp_verdict':10}  {'VT count from':16}" + "".join(f"{n:>8}" for n in names))
    for verdict in FLAGGED:
        sub = [x for x in rows if x["pp_verdict"] == verdict]
        for label, col in (("AndroZoo catalog", "az_vt_bucket"), ("VT report", "vt_bucket")):
            c = Counter(x[col] for x in sub)
            print(f"{verdict:10}  {label:16}" + "".join(f"{c[n]:>8}" for n in names))
    years = Counter(x["vt_last_analysis"][:4] for x in rows if x["vt_last_analysis"])
    print("\nVT report last analysed in: " + ", ".join(f"{y}: {n}" for y, n in sorted(years.items())))
    lacking = Counter(x["vt_status"] for x in rows if x["vt_status"] != "found")
    if lacking:
        print(f"note: no VT report for {sum(lacking.values())} app(s) {dict(lacking)} "
              f"(pending = not in {args.vt_dir}/ yet: run vt_lookup.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
