#!/usr/bin/env bash
#
# Progress + health snapshot of a capture run (reads results.csv — no database).
#
# Usage: status.sh <out_dir> [target_count] [manifest.csv]
#   out_dir       run output directory (holds results.csv)
#   target_count  expected total, for the progress bar (default: unknown)
#   manifest.csv  sample manifest with `sha256` and `year` columns, to show the
#                 per-year block rate (the key data-health check)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

OUT="${1:?output dir required}"
TARGET="${2:-0}"
MANIFEST="${3:-}"

echo "=================  RUN STATUS  ================="
echo "time   : $(date '+%Y-%m-%d %H:%M:%S')"

st=$(adb get-state 2>/dev/null); [ -z "$st" ] && st="OFFLINE (USB disconnected)"
echo "phone  : $st"
pgrep -fl "collect.py" >/dev/null && echo "collect: RUNNING" || echo "collect: stopped"

python3 - "$OUT/results.csv" "$TARGET" "$MANIFEST" <<'PY'
import csv, os, sys
from collections import Counter, defaultdict
results_csv, target, manifest = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if not os.path.exists(results_csv):
    print("\n(no results.csv yet)"); raise SystemExit

with open(results_csv, newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))
# Latest row per sha256 (highest result_id).
latest = {}
for r in rows:
    sha = r.get("sha256")
    if sha and (sha not in latest or int(r.get("result_id") or 0) >= int(latest[sha].get("result_id") or 0)):
        latest[sha] = r
d = len(latest)
if target:
    pct = 100 * d / target; bar = int(pct / 2.5)
    print(f"\nprogress : {d}/{target}  ({pct:.1f}%)")
    print("  [" + "#" * bar + "-" * (40 - bar) + "]")
else:
    print(f"\nprocessed: {d} APKs")

year = {}
if manifest and os.path.exists(manifest):
    with open(manifest, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            year[r["sha256"]] = r.get("year", "?")

BLOCK = {"blocked_by_play_protect"}
VERDICT = {"blocked_by_play_protect", "installed_no_alert", "installed_after_alert"}
agg = defaultdict(lambda: [0, 0]); tot = Counter()
for sha, r in latest.items():
    o = r.get("outcome"); tot[o] += 1
    if o in VERDICT:
        y = year.get(sha, "?"); agg[y][0] += 1
        if o in BLOCK: agg[y][1] += 1
if year:
    print("\nblock rate by year:")
    for y in sorted(agg):
        v, b = agg[y]
        print(f"  {y:>5} : {b:3}/{v:<3}  {100*b/v if v else 0:3.0f}%")
print("\noutcomes:")
for o, n in tot.most_common():
    print(f"  {o:28} {n}")
PY
echo "================================================"
