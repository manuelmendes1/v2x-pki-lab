#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo '[INFO] Lab is not a Git repository yet; no Git staging operation performed.'
  exit 0
fi

bad=0
while IFS= read -r -d '' f; do
  rel="${f#"$ROOT"/}"
  if ! git -C "$ROOT" check-ignore -q -- "$rel"; then
    echo "[WARNING] Credential-like file is not ignored: $rel"
    bad=1
  else
    echo "[PASS] ignored: $rel"
  fi
done < <(find "$ROOT/pki" "$ROOT/protocols" -type f \
  \( -name '*.key' -o -name '*.pem' -o -name '*.p8' -o -name '*.pk8' \
     -o -name '*.p12' -o -name '*.pfx' \) -print0)

if (( bad == 0 )); then echo 'GIT_CREDENTIAL_SAFETY=PASS'; else echo 'GIT_CREDENTIAL_SAFETY=FAIL'; fi
exit "$bad"
