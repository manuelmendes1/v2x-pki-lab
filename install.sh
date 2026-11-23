#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-$HOME/final/v2x-pki-lab}"

case "$DEST" in
  ""|"/") echo "[ERROR] Refusing unsafe destination: '$DEST'" >&2; exit 2 ;;
esac

if [[ -e "$DEST" ]]; then
  echo "[ERROR] Destination already exists; nothing was overwritten: $DEST" >&2
  exit 3
fi

mkdir -p "$(dirname -- "$DEST")"
mkdir -p "$DEST"
cp -a "$SOURCE_DIR/." "$DEST/"

# Ensure private/generated credential directories exist but remain empty.
find "$DEST/pki" "$DEST/protocols" -type d \
  \( -name root -o -name aa -o -name trust-store -o -name revocation \
     -o -name references -o -name evidence -o -name dual-aid \) \
  -exec sh -c 'for d do touch "$d/.gitkeep"; done' sh {} +

echo "[INSTALL] PASS"
echo "[DESTINATION] $DEST"
echo "[NEXT] cd '$DEST' && ./tools/validate-layout.sh"
