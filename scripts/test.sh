#!/usr/bin/env bash
# All tests. Usage: scripts/test.sh
# Locally a missing toolchain is a SKIP (and says so). In CI (CI=true) it is a failure.
set -u
cd "$(dirname "$0")/.."
fail=0
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" && return 0; if [ -n "${CI:-}" ]; then echo "   FAIL: $1 is required in CI"; fail=1; else echo "   SKIP: $1 not installed"; fi; return 1; }

echo "== script tests"
for t in scripts/tests/*.test.sh; do
  [ -f "$t" ] || continue
  bash "$t" || { echo "   FAIL: $t"; fail=1; }
done
if [ -f packages/mawaddah_protocol/pubspec.yaml ]; then
  echo "== dart test (mawaddah_protocol)"
  if need dart; then (cd packages/mawaddah_protocol && dart test) || fail=1; fi
fi
if [ -f relay/package.json ]; then
  echo "== npm test (relay)"
  if need npm; then (cd relay && npm ci --silent && npm test --if-present) || fail=1; fi
fi

if [ "$fail" -eq 0 ]; then echo "tests OK"; else echo "tests FAILED"; exit 1; fi
