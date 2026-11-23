#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 RUN_DIRECTORY [INDEPENDENT_CHECKER]" >&2
  exit 64
fi
RUN_DIR="$(cd "$1" && pwd)"
CHECKER="${2:-${C02_SIGCHECK_BIN:-}}"
if [[ -z "$CHECKER" || ! -x "$CHECKER" ]]; then
  echo "[ERROR] pass the independently compiled c02-chain-sigcheck binary" >&2
  echo "        or set C02_SIGCHECK_BIN" >&2
  exit 2
fi

ROOT="$RUN_DIR/authorities/root/root.cert"
AA="$RUN_DIR/authorities/aa/aa.cert"
TICKETS="$RUN_DIR/issued-tickets/dual-aid"
if [[ ! -s "$ROOT" || ! -s "$AA" || ! -d "$TICKETS" ]]; then
  echo "[ERROR] run directory has no expected Root/AA/AT layout" >&2
  exit 2
fi

TMP="$(mktemp -d /tmp/v2x-standard-v3-independent-check.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
ln -s "$ROOT" "$TMP/denm-root.cert"
ln -s "$AA" "$TMP/denm-aa.cert"

shopt -s nullglob
CERTS=( "$TICKETS"/*-ticket-000.cert )
if [[ ${#CERTS[@]} -eq 0 ]]; then
  echo "[ERROR] no AT certificates found in $TICKETS" >&2
  exit 2
fi

PASS=0
FAIL=0
for cert in "${CERTS[@]}"; do
  ln -sfn "$cert" "$TMP/veh0-ticket-000.cert"
  LOG="$TMP/check.log"
  if "$CHECKER" "$TMP" >"$LOG" 2>&1 && \
     grep -q '\[PRIMARY_SIGNATURE_CHAIN\] PASS' "$LOG" && \
     grep -q '\[AT_VEH0_PRIMARY_SIGNATURE\] SIGNATURE_VALID' "$LOG"; then
    echo "[PASS] $(basename "$cert")"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] $(basename "$cert")"
    grep -E 'SIGNATURE_INVALID|UNVERIFIABLE|FATAL|PRIMARY_SIGNATURE_CHAIN' "$LOG" || true
    FAIL=$((FAIL + 1))
  fi
done

echo "INDEPENDENT_AT_SIGNATURES_PASS=$PASS"
echo "INDEPENDENT_AT_SIGNATURES_FAIL=$FAIL"
echo "INDEPENDENT_AT_SIGNATURE_AUDIT=$([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL)"
[[ "$FAIL" -eq 0 ]]
