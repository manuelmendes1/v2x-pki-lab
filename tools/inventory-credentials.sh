#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

printf 'LAB_ROOT=%s\n' "$ROOT"
found=0
while IFS= read -r -d '' file; do
  rel="${file#"$ROOT"/}"
  case "$file" in
    *.key|*.pem|*.p8|*.pk8|*.p12|*.pfx|*.der|*.oer|*.cert)
      printf '[CREDENTIAL_FILE] %s (%s bytes)\n' "$rel" "$(stat -c '%s' "$file")"
      found=$((found + 1))
      ;;
  esac
done < <(find "$ROOT/pki" "$ROOT/protocols" -type f -print0)

if (( found == 0 )); then
  echo 'CREDENTIAL_PAYLOADS=NONE'
else
  echo "CREDENTIAL_PAYLOAD_FILES=$found"
  echo 'NOTE=Inventory only; file presence does not imply validity or trust.'
fi
