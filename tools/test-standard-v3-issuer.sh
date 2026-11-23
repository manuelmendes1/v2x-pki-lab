#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$LAB_ROOT/tools/standard-v3-issuer/tests" -v
"$LAB_ROOT/tools/build-standard-v3-issuer.sh"

BIN="$LAB_ROOT/build/standard-v3-issuer/standard-v3-issuer"
OUTPUT="$($BIN --lab-root "$LAB_ROOT" --vehicles 2 --root-days 365 --aa-days 180 --ticket-days 30 --dry-run)"
printf '%s\n' "$OUTPUT"

grep -q '^ISSUER_PROFILE=standard$' <<<"$OUTPUT"
grep -q '^ROOT_ISSUE_AIDS=36,37$' <<<"$OUTPUT"
grep -q '^AA_ISSUE_AIDS=36,37$' <<<"$OUTPUT"
grep -q '^AT_APPLICATION_AIDS=36,37$' <<<"$OUTPUT"
grep -q '^VEHICLE_COUNT=2$' <<<"$OUTPUT"
grep -q '^FILES_WRITTEN=0$' <<<"$OUTPUT"
grep -q '^DRY_RUN=PASS$' <<<"$OUTPUT"

if "$BIN" --lab-root "$LAB_ROOT" --vehicles 2 --root-days 30 --aa-days 60 --ticket-days 7 --dry-run >/dev/null 2>&1; then
  echo "[ERROR] expected invalid nested validity to be rejected" >&2
  exit 1
fi

echo "STANDARD_V3_ISSUER_DRY_RUN_TEST=PASS"
