#!/usr/bin/env bash
# Tests for scripts/release-notes.sh
cd "$(dirname "$0")/../.." || exit 1
fail=0
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<'CL'
# Changelog

## [Unreleased]

### Added
- not yet released

## [0.2.0] - 2026-02-01

### Added
- second

## [0.1.0] - 2026-01-01

### Added
- first

## [0.0.9] - 2025-12-01
CL
out=$(scripts/release-notes.sh v0.2.0 "$tmp") || { echo "FAIL: v0.2.0 should extract"; fail=1; }
case "$out" in *"- second"*) ;; *) echo "FAIL: missing v0.2.0 content"; fail=1;; esac
case "$out" in *"- first"*|*"not yet released"*) echo "FAIL: leaked other sections"; fail=1;; esac
scripts/release-notes.sh v0.1.0 "$tmp" | grep -q -- "- first" || { echo "FAIL: v0.1.0"; fail=1; }
scripts/release-notes.sh v9.9.9 "$tmp" >/dev/null 2>&1 && { echo "FAIL: missing section should fail"; fail=1; }
scripts/release-notes.sh v0.0.9 "$tmp" >/dev/null 2>&1 && { echo "FAIL: empty section should fail"; fail=1; }
scripts/release-notes.sh main "$tmp" >/dev/null 2>&1 && { echo "FAIL: non-tag should fail"; fail=1; }
[ "$fail" -eq 0 ] && echo "release-notes tests OK"
exit "$fail"
