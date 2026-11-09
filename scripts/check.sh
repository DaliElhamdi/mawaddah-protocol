#!/usr/bin/env bash
# Format + lint + fast checks.   Usage: scripts/check.sh [--quick]
# Locally a missing tool is a SKIP (and says so). In CI (CI=true) a missing tool is a failure.
set -u
cd "$(dirname "$0")/.."
quick=0; [ "${1:-}" = "--quick" ] && quick=1
fail=0
step() { printf '== %s\n' "$1"; }
skip() { printf '   SKIP: %s\n' "$1"; }
bad()  { printf '   FAIL: %s\n' "$1"; fail=1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" && return 0; if [ -n "${CI:-}" ]; then bad "$1 is required in CI"; else skip "$1 not installed"; fi; return 1; }

step "shell syntax"
for f in scripts/*.sh scripts/tests/*.sh .githooks/commit-msg; do
  [ -f "$f" ] || continue
  bash -n "$f" || bad "syntax error in $f"
done

step "no private material (this repository is public)"
if git ls-files 2>/dev/null | grep -Ei '(^|/)(\.env[^/]*|[^/]*\.(jks|keystore|p12|pem|mobileprovision)|google-services\.json|service-account[^/]*\.json)$'; then
  bad "secret-like file is tracked"
fi

if [ -f packages/mawaddah_protocol/pubspec.yaml ]; then
  step "dart format + analyze (mawaddah_protocol)"
  if need dart; then
    dart format --output=none --set-exit-if-changed packages/mawaddah_protocol || bad "dart format"
    (cd packages/mawaddah_protocol && dart analyze) || bad "dart analyze"
  fi
fi
if [ -f relay/package.json ]; then
  step "relay lint"
  if need npm; then (cd relay && npm ci --silent && npm run lint --if-present) || bad "relay lint"; fi
fi

if [ "$fail" -eq 0 ]; then echo "check OK"; else echo "check FAILED"; exit 1; fi
