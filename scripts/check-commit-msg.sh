#!/usr/bin/env bash
# Validates the first line of a commit message / PR title against .github/commit-types.txt.
# Usage: scripts/check-commit-msg.sh "<message>"      Exit 0 = valid, 1 = invalid.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
types_file="$root/.github/commit-types.txt"
msg="${1-}"
first="$(printf '%s\n' "$msg" | sed -n '/./{p;q}')"

case "$first" in
  "Merge "*|'Revert "'*|"fixup!"*|"squash!"*) exit 0 ;;
esac

types=(); scopes=(); section=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="${line//[[:space:]]/}"
  [ -z "$line" ] && continue
  case "$line" in
    "[types]")  section=types ;;
    "[scopes]") section=scopes ;;
    *) if [ "$section" = types ]; then types+=("$line"); elif [ "$section" = scopes ]; then scopes+=("$line"); fi ;;
  esac
done < "$types_file"

[ "${#types[@]}" -gt 0 ] || { echo "check-commit-msg: no [types] in $types_file" >&2; exit 1; }
join() { local IFS='|'; echo "$*"; }
t="$(join "${types[@]}")"
if [ "${#scopes[@]}" -gt 0 ]; then s="$(join "${scopes[@]}")"; else s='[a-z0-9._/-]+'; fi
re="^(${t})(\((${s})\))?!?: .{1,72}$"

if [[ "$first" =~ $re ]]; then exit 0; fi
{
  echo "Invalid commit message / PR title: \"$first\""
  echo "Expected:  type(scope): subject   (subject 1-72 chars)"
  echo "Types:     ${t//|/, }"
  [ "${#scopes[@]}" -gt 0 ] && echo "Scopes:    ${s//|/, }"
} >&2
exit 1
