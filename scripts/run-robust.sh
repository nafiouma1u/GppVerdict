#!/usr/bin/env bash
#
# Robust, resumable capture run.
#
# Re-runs collect.py until results.csv holds TARGET distinct APKs, regardless of exit
# code, so a transient network/USB drop (which can make collect.py exit cleanly having
# done nothing) is retried instead of being mistaken for success. Wrap with
# caffeinate + nohup so it survives sleep and a closed terminal:
#
#   nohup caffeinate -dimsu bash scripts/run-robust.sh \
#         Data/sample.tsv results_run 3500 >> run.log 2>&1 & disown
#
# Usage: run-robust.sh <catalog.tsv> <out_dir> <target_count> [extra collect.py args...]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

CATALOG="${1:?catalog .tsv required}"
OUT="${2:?output dir required}"
TARGET="${3:?target APK count required}"
shift 3
EXTRA=("$@")

count() {
  python3 -c "
import csv
p='$OUT/results.csv'
try:
    with open(p, newline='', encoding='utf-8-sig') as f:
        print(len({r['sha256'] for r in csv.DictReader(f) if r.get('sha256')}))
except FileNotFoundError:
    print(0)
" 2>/dev/null || echo 0
}

while true; do
  before=$(count)
  if [ "$before" -ge "$TARGET" ]; then
    echo "✓ DONE: $before/$TARGET ($(date))"; break
  fi
  echo "▶ launch — done: $before/$TARGET ($(date))"
  python collect.py --catalog "$CATALOG" --all --out "$OUT" --no-scan --resume ${EXTRA[@]+"${EXTRA[@]}"}
  after=$(count)
  if [ "$after" -ge "$TARGET" ]; then
    echo "✓ DONE: $after/$TARGET ($(date))"; break
  fi
  if [ "$after" -le "$before" ]; then
    echo "⏳ no progress (phone offline / USB dropped?) — retrying in 120s…"
    sleep 120
  fi
done
