#!/usr/bin/env bash
#
# release-guard-test.sh — drive scripts/release-guard.sh against deliberately
# broken input.
#
# The guard's whole job is to fail, and the release path only ever runs it on
# input that is expected to pass; left at that, the failure branches would be
# dead code that nobody has executed since the day they were written. So each
# rule it enforces gets a fixture here that breaks exactly that rule, plus the
# passing cases to prove it is not simply refusing everything.
#
# The comparison rule worth singling out is the pre-release one: `sort -V`, the
# obvious implementation, orders 1.2.3 *before* 1.2.3-rc.1, which would let a
# release candidate be published as newer than the release it was a candidate
# for. There is a case for that below.
#
# Run it directly (`scripts/release-guard-test.sh`) or via `make release-check`.
# It needs nothing but bash and the checkout, and the release workflow runs it
# in the guard job before the guard itself.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${HERE}/release-guard.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASSED=0
FAILED=0

# changelog <file> <<'EOF' … EOF — write a fixture changelog.
changelog() { cat >"${WORK}/$1"; }

gomod() { # <file> <module-path>
	printf 'module %s\n\ngo 1.25.7\n' "$2" >"${WORK}/$1"
}

# expect_ok <name> <args…> — the guard must accept this input.
expect_ok() {
	local name="$1"
	shift
	local out status=0
	out="$("$GUARD" "$@" 2>&1)" || status=$?
	if [ "$status" -eq 0 ]; then
		PASSED=$((PASSED + 1))
		printf '  ok    %s\n' "$name"
	else
		FAILED=$((FAILED + 1))
		printf '  FAIL  %s — expected acceptance, got exit %d:\n%s\n' "$name" "$status" "$out"
	fi
}

# expect_fail <name> <substring> <args…> — the guard must reject this input,
# and say why. The substring is checked because a guard that fails for the
# wrong reason is indistinguishable from one that works until you need it.
expect_fail() {
	local name="$1" want="$2"
	shift 2
	local out status=0
	out="$("$GUARD" "$@" 2>&1)" || status=$?
	if [ "$status" -eq 0 ]; then
		FAILED=$((FAILED + 1))
		printf '  FAIL  %s — expected rejection, but it passed:\n%s\n' "$name" "$out"
	elif ! printf '%s' "$out" | grep -qF -- "$want"; then
		FAILED=$((FAILED + 1))
		printf '  FAIL  %s — rejected, but not for the expected reason (wanted %q):\n%s\n' "$name" "$want" "$out"
	else
		PASSED=$((PASSED + 1))
		printf '  ok    %s\n' "$name"
	fi
}

# --------------------------------------------------------------------------- #
echo "release-guard.sh"

changelog good.md <<'EOF'
# Changelog

## [Unreleased]

## [1.2.3] - 2026-08-18
### Added
- A thing.

## [1.2.2] - 2026-08-01
### Fixed
- Another thing.
EOF
gomod good.mod github.com/blechschmidt/secsy-pki/server

GOOD=(--changelog "${WORK}/good.md" --gomod "${WORK}/good.mod")

expect_ok "accepts a tag whose section is newest, dated and non-empty" \
	--ref refs/tags/v1.2.3 "${GOOD[@]}"

expect_ok "accepts a dry run with no tag (version from the changelog)" \
	"${GOOD[@]}"

expect_ok "accepts a matching module path" \
	--ref refs/tags/v1.2.3 --repository blechschmidt/secsy-pki "${GOOD[@]}"

expect_fail "rejects a module path that is not this repository's" \
	"declares module" \
	--ref refs/tags/v1.2.3 --repository someone-else/secsy-pki "${GOOD[@]}"

expect_fail "rejects a tag with no changelog section" \
	"has no section for 9.9.9" \
	--ref refs/tags/v9.9.9 "${GOOD[@]}"

expect_fail "rejects a released version that is not the newest section" \
	"sits above it" \
	--ref refs/tags/v1.2.2 "${GOOD[@]}"

expect_fail "rejects a tag that is not semver" \
	"is not a semantic version" \
	--ref refs/tags/v1.2 "${GOOD[@]}"

expect_fail "rejects a tag without the v prefix" \
	"prefixed with 'v'" \
	--ref refs/tags/1.2.3 "${GOOD[@]}"

expect_fail "rejects a ref that is not a tag" \
	"must be a tag ref" \
	--ref refs/heads/enterprise "${GOOD[@]}"

# --- the section itself ------------------------------------------------------
changelog undated.md <<'EOF'
# Changelog

## [1.2.3]
- A thing.
EOF
expect_fail "rejects an undated section" \
	"is undated" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/undated.md"

changelog baddate.md <<'EOF'
# Changelog

## [1.2.3] - 2026-02-31
- A thing.
EOF
expect_fail "rejects a date that is not a real day" \
	"not a real date" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/baddate.md"

changelog empty.md <<'EOF'
# Changelog

## [1.2.3] - 2026-08-18

## [1.2.2] - 2026-08-01
- A thing.
EOF
expect_fail "rejects an empty section" \
	"is empty" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/empty.md"

changelog none.md <<'EOF'
# Changelog

## [Unreleased]
- Nothing released yet.
EOF
expect_fail "rejects a changelog with no released section" \
	"no released section" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/none.md"

# --- ordering ----------------------------------------------------------------
changelog backwards.md <<'EOF'
# Changelog

## [1.2.3] - 2026-08-18
- A thing.

## [1.3.0] - 2026-08-01
- An older section for a newer version.
EOF
expect_fail "rejects released sections that do not descend" \
	"must descend" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/backwards.md"

changelog tenths.md <<'EOF'
# Changelog

## [1.10.0] - 2026-08-18
- Ten is after nine.

## [1.9.0] - 2026-08-01
- A thing.
EOF
expect_ok "orders 1.10.0 above 1.9.0 (numeric, not lexical)" \
	--ref refs/tags/v1.10.0 --changelog "${WORK}/tenths.md"

# The `sort -V` trap: a pre-release precedes its release, so 1.2.3 belongs
# *above* 1.2.3-rc.1 and 1.2.3-rc.1 above nothing but older versions.
changelog prerelease.md <<'EOF'
# Changelog

## [1.2.3] - 2026-08-18
- The release.

## [1.2.3-rc.2] - 2026-08-17
- Second candidate.

## [1.2.3-rc.1] - 2026-08-16
- First candidate.

## [1.2.2] - 2026-08-01
- A thing.
EOF
expect_ok "orders a release above its own release candidates" \
	--ref refs/tags/v1.2.3 --changelog "${WORK}/prerelease.md"

changelog rc-above.md <<'EOF'
# Changelog

## [1.2.3-rc.1] - 2026-08-18
- A candidate, listed as if it superseded the release.

## [1.2.3] - 2026-08-01
- The release.
EOF
expect_fail "rejects a release candidate listed above its own release" \
	"must descend" \
	--ref refs/tags/v1.2.3-rc.1 --changelog "${WORK}/rc-above.md"

# --- outputs -----------------------------------------------------------------
out_file="${WORK}/outputs"
notes_file="${WORK}/notes.md"
: >"$out_file"
GITHUB_OUTPUT="$out_file" "$GUARD" --ref refs/tags/v1.2.3 --notes "$notes_file" \
	"${GOOD[@]}" >/dev/null

check_output() { # <key=value>
	if grep -qx -- "$1" "$out_file"; then
		PASSED=$((PASSED + 1))
		printf '  ok    emits %s\n' "$1"
	else
		FAILED=$((FAILED + 1))
		printf '  FAIL  expected %q among the step outputs:\n%s\n' "$1" "$(cat "$out_file")"
	fi
}
check_output "version=1.2.3"
check_output "tag=v1.2.3"
check_output "minor=1.2"
check_output "prerelease=false"

if grep -q "A thing." "$notes_file" && ! grep -q "Another thing." "$notes_file"; then
	PASSED=$((PASSED + 1))
	printf '  ok    writes the release notes of that section and no other\n'
else
	FAILED=$((FAILED + 1))
	printf '  FAIL  the notes file holds the wrong section:\n%s\n' "$(cat "$notes_file")"
fi

# A candidate is cut while it is still the newest section — its release does not
# exist yet, which is the state a pre-release is released from.
changelog rc-newest.md <<'EOF'
# Changelog

## [1.2.3-rc.1] - 2026-08-16
- First candidate.

## [1.2.2] - 2026-08-01
- A thing.
EOF
: >"$out_file"
GITHUB_OUTPUT="$out_file" "$GUARD" --ref refs/tags/v1.2.3-rc.1 \
	--changelog "${WORK}/rc-newest.md" >/dev/null
check_output "prerelease=true"
check_output "minor=1.2"

# --------------------------------------------------------------------------- #
echo
if [ "$FAILED" -ne 0 ]; then
	echo "release-guard.sh: ${FAILED} failed, ${PASSED} passed"
	exit 1
fi
echo "release-guard.sh: all ${PASSED} checks passed"
