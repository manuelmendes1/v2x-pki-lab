#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
required=(
  README.md docs/architecture.md docs/current-baseline.md docs/provisioning-gap.md
  config/domains/vehicle-v3.yaml config/domains/rsu-spatem-v3.yaml config/domains/cpm-v3.yaml
  config/protocols/cam.yaml config/protocols/denm.yaml config/protocols/cpm.yaml
  config/protocols/spatem.yaml config/protocols/vam.yaml
  protocols/cam protocols/denm protocols/cpm protocols/spatem protocols/vam protocols/_template
  pki/domains/vehicle-v3 pki/domains/rsu-spatem-v3 pki/domains/cpm-v3
)
fail=0
for item in "${required[@]}"; do
  if [[ -e "$ROOT/$item" ]]; then
    printf '[PASS] %s\n' "$item"
  else
    printf '[FAIL] %s\n' "$item"
    fail=1
  fi
done

# Guard key architectural invariants in manifests.
grep -q '^protocols: \[cam, denm\]' "$ROOT/config/domains/vehicle-v3.yaml" \
  && echo '[PASS] CAM/DENM share vehicle-v3 domain' || { echo '[FAIL] vehicle domain mapping'; fail=1; }
grep -q '^security_domain: rsu-spatem-v3$' "$ROOT/config/protocols/spatem.yaml" \
  && echo '[PASS] SPATEM uses RSU domain' || { echo '[FAIL] SPATEM domain mapping'; fail=1; }
grep -q '^security_domain: cpm-v3$' "$ROOT/config/protocols/cpm.yaml" \
  && echo '[PASS] CPM uses separate domain' || { echo '[FAIL] CPM domain mapping'; fail=1; }
grep -q '^issuance_enabled: false$' "$ROOT/config/protocols/vam.yaml" \
  && echo '[PASS] VAM issuance disabled' || { echo '[FAIL] VAM issuance guard'; fail=1; }

if (( fail == 0 )); then
  echo 'LAYOUT_VALIDATION=PASS'
else
  echo 'LAYOUT_VALIDATION=FAIL'
fi
exit "$fail"
