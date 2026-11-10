#!/usr/bin/env bash
# Print the CHANGELOG section for a release tag.   Usage: scripts/release-notes.sh v0.0.1 [CHANGELOG.md]
# Fails if the tag is malformed or the section is missing or empty.
set -eu
tag="${1:?usage: release-notes.sh vX.Y.Z [changelog]}"
file="${2:-$(dirname "$0")/../CHANGELOG.md}"
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "not a release tag: $tag" >&2; exit 1 ;;
esac
version="${tag#v}"
notes=$(awk -v v="$version" '
  /^## \[/ { if (on) exit; on = (index($0, "## [" v "]") == 1); next }
  on { print }
' "$file" | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba' -e '}' | sed '/./,$!d')
if [ -z "$notes" ]; then
  echo "CHANGELOG has no (or an empty) section for [$version]" >&2
  exit 1
fi
printf '%s\n' "$notes"
