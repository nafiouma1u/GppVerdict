#!/usr/bin/env python3
"""Draw a RANDOM sample stratified by year from the AndroZoo catalog.

By default: 500 APKs per year, 2020 to 2026 inclusive, at random. The year is the
`added` field (entry into AndroZoo) — the same field the rest of the pipeline uses as
the "year", and the only one with enough volume in recent years (dex_date collapses
after 2023).

Reservoir sampling (algorithm R), a single streaming pass over the file, fixed seed →
reproducible draw. Sampling is at the APK (sha256) level: each kept row is a distinct
file to install.

Output:
  - a valid TSV sub-catalog (same columns as the original) that collect.py consumes
    via `--catalog ... --all`;
  - a readable CSV manifest (pkg_name, sha256, year, vt_detection, size).

    python sample_years.py --catalog "Data/gone_apps.tsv" \\
        --per-year 500 --year-min 2020 --year-max 2026 --seed 1 \\
        --out-tsv "Data/sample_2020_2026.tsv" --out-csv "report/sample_2020_2026.csv"
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

from gppverdict import catalog


def year_of(row: dict) -> int | None:
    val = row.get("added") or row.get("first_added") or row.get("vt_scan_date") or ""
    try:
        return int(val[:4])
    except (TypeError, ValueError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Random year-stratified sampling (AndroZoo).")
    ap.add_argument("--catalog", default="Data/gone_apps.tsv",
                    help="AndroZoo catalog (.tsv, .csv, .gz, .tar.gz). Default: Data/gone_apps.tsv")
    ap.add_argument("--per-year", type=int, default=500, help="APKs drawn per year (default: 500)")
    ap.add_argument("--year-min", type=int, default=2020, help="First year (default: 2020)")
    ap.add_argument("--year-max", type=int, default=2026, help="Last year included (default: 2026)")
    ap.add_argument("--max-size-mb", type=float, default=None,
                    help="Exclude APKs larger than N MB (default: no limit)")
    ap.add_argument("--seed", type=int, default=1, help="Sampling seed (default: 1)")
    ap.add_argument("--exclude", nargs="*", default=[],
                    help="Run directories whose already-processed sha256 are EXCLUDED from the draw")
    ap.add_argument("--out-tsv", default="Data/sample_2020_2026.tsv",
                    help="Output TSV sub-catalog (installable by collect.py)")
    ap.add_argument("--out-csv", default="report/sample_2020_2026.csv",
                    help="Readable CSV manifest")
    args = ap.parse_args()

    path = Path(args.catalog)
    if not path.exists():
        print(f"Catalog not found: {path}", file=sys.stderr)
        return 1

    # Already-processed sha256 to exclude (union of the given run directories).
    exclude: set[str] = set()
    for run_dir in args.exclude:
        p2 = Path(run_dir)
        results_csv = p2 / "results.csv" if p2.is_dir() else p2
        if not results_csv.exists():
            print(f"  (exclusion ignored, file missing: {results_csv})", file=sys.stderr)
            continue
        with open(results_csv, newline="", encoding="utf-8-sig") as f:
            exclude |= {r["sha256"] for r in csv.DictReader(f) if r.get("sha256")}
    if exclude:
        print(f"Exclusion: {len(exclude)} already-processed sha256 will be skipped.", file=sys.stderr)

    years = list(range(args.year_min, args.year_max + 1))
    max_size = args.max_size_mb * 1e6 if args.max_size_mb else None
    rng = random.Random(args.seed)
    reservoir: dict[int, list[dict]] = {y: [] for y in years}
    seen: dict[int, int] = {y: 0 for y in years}
    header: list[str] = []

    print(f"Reading {path.name} … drawing {args.per_year}/year for {years[0]}–{years[-1]} "
          f"(seed {args.seed})", file=sys.stderr)
    scanned = 0
    for row in catalog.iter_rows(path):
        if not header:
            header = list(row.keys())
        scanned += 1
        if scanned % 1_000_000 == 0:
            print(f"  … {scanned:,} rows scanned", file=sys.stderr)
        y = year_of(row)
        if y not in reservoir:
            continue
        sha = row.get("sha256")
        if not sha or len(sha) != 64:
            continue
        if sha in exclude:
            continue
        if max_size:
            try:
                if int(float(row.get("apk_size", 0))) > max_size:
                    continue
            except (TypeError, ValueError):
                continue
        seen[y] += 1
        res = reservoir[y]
        if len(res) < args.per_year:
            res.append(row)
        else:  # random replacement (reservoir, algorithm R)
            j = rng.randint(0, seen[y] - 1)
            if j < args.per_year:
                res[j] = row

    # Gather, by increasing year, then shuffle globally (neutral install order).
    selected = [r for y in years for r in reservoir[y]]
    rng.shuffle(selected)

    # TSV sub-catalog (same columns → valid catalog for collect.py).
    out_tsv = Path(args.out_tsv)
    out_tsv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_tsv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(header)
        for r in selected:
            w.writerow([r.get(c, "") for c in header])

    # Readable CSV manifest.
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["year", "pkg_name", "sha256", "vt_detection", "apk_size_mb", "dex_date", "added"])
        for r in sorted(selected, key=lambda r: (year_of(r) or 0, r.get("pkg_name", ""))):
            try:
                size_mb = f"{int(float(r.get('apk_size', 0))) / 1e6:.1f}"
            except (TypeError, ValueError):
                size_mb = ""
            w.writerow([year_of(r), r.get("pkg_name"), r.get("sha256"),
                        r.get("vt_detection"), size_mb, r.get("dex_date"), r.get("added")])

    # Summary.
    print("\n" + "=" * 52)
    print(f"  SAMPLE — {len(selected)} APKs")
    print("=" * 52)
    for y in years:
        got, pool = len(reservoir[y]), seen[y]
        flag = "" if got == args.per_year else "  ⚠ fewer than requested"
        print(f"    {y} : {got:4}/{args.per_year}  (out of {pool:,} available){flag}")
    print(f"\n  Sub-catalog : {out_tsv}")
    print(f"  CSV manifest: {out_csv}")
    print(f"\n  To install and capture alerts:")
    print(f'    python collect.py --catalog "{out_tsv}" --all --out results_sample --no-scan')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
