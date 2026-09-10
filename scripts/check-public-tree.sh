#!/bin/sh
# Public-tree hygiene.
#
# Refuses to call this checkout publishable while it tracks files that are
# private, generated, or machine-specific, or while tracked text leaks an
# absolute developer path. `.gitignore` only stops *new* files from being
# added — a file that was tracked before a rule existed stays tracked — so the
# check has to look at what git actually carries, not at the ignore rules.
#
# Run it with `make hygiene`; CI runs it too, so the rules cannot rot.

set -eu

cd "$(dirname "$0")/.."

fail=0

# forbidden reports whether a tracked path must never be published.
forbidden() {
	case "$1" in
	# Build and release output.
	dist/* | wpus | wpus.exe | *.test | *.out | *.prof) return 0 ;;
	# Tooling packs, caches, OS and editor state.
	repomix-output* | .DS_Store | */.DS_Store | .env | .env.*) return 0 ;;
	# Local-only policy overrides and secret material.
	.wpus.local.yaml | .wpus.local.yml | *.pem | *.key | *.p12 | *.pfx) return 0 ;;
	# Generated scan output.
	*.sarif | result.json | results.json) return 0 ;;
	# Private documentation: research dumps, internal notes, maintainer scratch.
	docs/research/* | docs/private/* | docs/internal/*) return 0 ;;
	*-internal.md | *.private.md | *.local.md) return 0 ;;
	esac
	# Dated research folders, both naming conventions (docs/11:09:2026/... and
	# docs/2026-09-11/...).
	case "$1" in
	docs/?[0-9]:[0-9][0-9]:[0-9][0-9][0-9][0-9]/*) return 0 ;;
	docs/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/*) return 0 ;;
	esac
	return 1
}

tracked="$(git ls-files)"
if [ -z "$tracked" ]; then
	echo "hygiene: no tracked files (not a git checkout?)" >&2
	exit 1
fi

while IFS= read -r file; do
	[ -n "$file" ] || continue
	if forbidden "$file"; then
		printf 'hygiene: tracked but private or generated: %s\n' "$file"
		fail=1
	fi
done <<EOF
$tracked
EOF

# An absolute developer path in a tracked file leaks a machine layout and is
# never intentional here. Test files and fixtures are excluded: they contain
# synthetic paths on purpose.
#
# Documentation is scanned too, but a documented placeholder (`/home/you/...`)
# is legitimate. The filter below drops matches whose owner segment is a
# documented stand-in while a real path still fails the check.
scan_developer_paths() {
	git grep -nIE '/Users/[A-Za-z][A-Za-z0-9._-]*|/home/[a-z][a-z0-9._-]*|C:\\\\Users\\\\' -- \
		. ':(exclude)*_test.go' ':(exclude)testdata/**' 2>/dev/null |
		grep -vE '/(you|user|username|name|example|me|someone|youruser)(/|$)|C:\\\\Users\\\\(<|USER|username)' || true
}

if [ -n "$(scan_developer_paths)" ]; then
	echo "hygiene: tracked file contains an absolute developer path:" >&2
	scan_developer_paths >&2
	fail=1
fi

# Belt and braces: the ignore rules must still hide the private paths that are
# present in the working tree. A rule that silently stops matching (a renamed
# folder, a typo in a pattern) would let the next `git add -A` publish them.
for private in docs/11:09:2026 repomix-output.xml dist wpus; do
	[ -e "$private" ] || continue
	# A tracked path is reported by the first check; check-ignore says nothing
	# about tracked files, so asking it here would only add noise.
	if git ls-files --error-unmatch "$private" >/dev/null 2>&1; then
		continue
	fi
	if ! git check-ignore -q "$private"; then
		printf 'hygiene: %s exists but is not covered by .gitignore\n' "$private"
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "hygiene: FAILED — fix the paths above before publishing" >&2
	exit 1
fi

printf 'hygiene: ok (%s tracked files, nothing private, generated, or machine-specific)\n' "$(printf '%s\n' "$tracked" | wc -l | tr -d ' ')"
