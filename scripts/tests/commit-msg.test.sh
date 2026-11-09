#!/usr/bin/env bash
# Tests for scripts/check-commit-msg.sh
cd "$(dirname "$0")/../.." || exit 1
fail=0
ok()  { scripts/check-commit-msg.sh "$1" >/dev/null 2>&1 || { echo "FAIL (should be valid): $1"; fail=1; }; }
bad() { scripts/check-commit-msg.sh "$1" >/dev/null 2>&1 && { echo "FAIL (should be invalid): $1"; fail=1; }; }

ok  "feat(relay): add inbox registration endpoint"
ok  "chore(tooling): add repository scaffolding"
ok  "docs(protocol): describe the pairing slot"
ok  "fix: reject replayed envelopes"
ok  "feat(crypto)!: change envelope format"
ok  "Merge branch 'x' into main"
ok  'Revert "feat: x"'
ok  "$(printf 'fix(sync): body follows\n\nCloses #1')"
bad "Add relay"
bad "feat(chat): not a scope in this repo"
bad "content(relay): not a type in this repo"
bad "feat(relay):x"
bad "feat(relay): "
bad ""

[ "$fail" -eq 0 ] && echo "commit-msg tests OK"
exit "$fail"
