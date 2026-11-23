#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${VANETZA_PREFIX:-$HOME/opt/vanetza-cpm-gcc11}"
CXX_COMPILER="${CXX:-/usr/bin/g++-11}"
BUILD_DIR="$LAB_ROOT/build/standard-v3-issuer"

if [[ ! -f "$PREFIX/lib/cmake/Vanetza/VanetzaConfig.cmake" ]]; then
  echo "[ERROR] Vanetza CMake package not found under $PREFIX" >&2
  exit 1
fi
if [[ ! -x "$CXX_COMPILER" ]]; then
  echo "[ERROR] C++ compiler not executable: $CXX_COMPILER" >&2
  exit 1
fi

cmake -S "$LAB_ROOT/tools/standard-v3-issuer" -B "$BUILD_DIR" \
  -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build "$BUILD_DIR" --parallel 2

COMPILE_COMMANDS="$BUILD_DIR/compile_commands.json"
if grep -q -- '-DVANETZA_WITH_PQC\| -DVANETZA_WITH_PQC' "$COMPILE_COMMANDS"; then
  echo "[ERROR] VANETZA_WITH_PQC leaked into standard issuer compile flags" >&2
  exit 1
fi

BIN="$BUILD_DIR/standard-v3-issuer"
"$BIN" --help >/dev/null

echo "STANDARD_V3_ISSUER_BUILD=PASS"
echo "ASN1_PROFILE=standard"
echo "VANETZA_PREFIX=$PREFIX"
echo "ISSUER_BINARY=$BIN"
