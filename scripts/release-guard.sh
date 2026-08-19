#!/usr/bin/env bash
#
# release-guard.sh — refuse a release before anything is built.
#
# Everything a release does after this point is either expensive (the full
# SoftHSM CI gate, two container architectures) or irreversible (a pushed image
# tag, a GitHub release, a signature in a public transparency log). So the facts
# that have to agree are checked here, first, on a checkout and nothing else:
#
#   1. The tag is a semantic version — `vX.Y.Z`, optionally `-<prerelease>`.
#   2. CHANGELOG.md has a dated, non-empty section for exactly that version, and
#      it is the newest one. That section becomes the GitHub release body, so a
#      release cannot be published with notes nobody wrote.
#   3. The released sections of the changelog are in descending version order,
#      which is how a version that goes backwards is caught.
#   4. server/go.mod's module path matches the repository the run is on. Go
#      resolves `go install github.com/<owner>/<repo>/server/cmd/…` by that path
#      and the cosign keyless identity is pinned to the same slug (see the
#      Makefile's COSIGN_CERT_IDENTITY_REGEXP), so a repository that was renamed
#      or forked without updating go.mod produces artifacts that fail to install
#      and signatures that fail to verify — a fact that otherwise surfaces only
#      after the publish, which is the one place it cannot be fixed.
#
# On a tag push the tag names the version. On a manual dry run there is no tag,
# so the newest changelog section names it instead: a dry run then checks exactly
# what the next tag will check.
#
# Usage:
#   release-guard.sh [--ref refs/tags/v1.2.3] [--repository owner/repo]
#                    [--changelog CHANGELOG.md] [--notes release-notes.md]
#
#   --ref         the pushed ref. Omit for a dry run (version taken from the
#                 changelog).
#   --repository  "owner/repo" (GitHub's ${{ github.repository }}); enables
#                 check 4. Omit to skip it.
#   --notes       write the release-note body of the section to this file.
#
# On success it prints the four facts and, under GitHub Actions, writes them to
# $GITHUB_OUTPUT: version (1.2.3), tag (v1.2.3), minor (1.2), prerelease
# (true|false).
#
# The comparison rules and the parsing are exercised by
# scripts/release-guard-test.sh, which drives this script against deliberately
# broken changelogs: a guard only exercised by the release it guards is not a
# guard.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

CHANGELOG="${REPO_ROOT}/CHANGELOG.md"
GOMOD="${REPO_ROOT}/server/go.mod"
REF=""
REPOSITORY=""
NOTES=""

fail() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::error::$*" >&2
	else
		echo "release-guard: error: $*" >&2
	fi
	exit 1
}

# --------------------------------------------------------------------------- #
# Semantic-version comparison
# --------------------------------------------------------------------------- #
#
# `sort -V` is not usable here: it orders 1.2.3 before 1.2.3-rc.1, and semver
# says a pre-release precedes its release. Getting that backwards would let
# 1.2.3-rc.1 be published as newer than the 1.2.3 it was a candidate for, so the
# rules are implemented rather than approximated.

semver_valid() { # <version>
	[[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
}

# Compare two versions; echo -1, 0 or 1 for a<b, a==b, a>b (semver §11).
semver_cmp() { # <a> <b>
	local a="$1" b="$2" a_core b_core a_pre b_pre
	a_core="${a%%-*}"
	b_core="${b%%-*}"
	a_pre=""
	b_pre=""
	[ "$a" != "$a_core" ] && a_pre="${a#*-}"
	[ "$b" != "$b_core" ] && b_pre="${b#*-}"

	local i x y
	local -a a_f b_f
	IFS=. read -r -a a_f <<<"$a_core"
	IFS=. read -r -a b_f <<<"$b_core"
	for i in 0 1 2; do
		x="${a_f[$i]:-0}"
		y="${b_f[$i]:-0}"
		if ((10#$x < 10#$y)); then
			echo -1
			return
		fi
		if ((10#$x > 10#$y)); then
			echo 1
			return
		fi
	done

	# Equal cores: a version *with* a pre-release is older than one without.
	if [ -z "$a_pre" ] && [ -z "$b_pre" ]; then
		echo 0
		return
	fi
	if [ -z "$a_pre" ]; then
		echo 1
		return
	fi
	if [ -z "$b_pre" ]; then
		echo -1
		return
	fi

	# Both pre-releases: compare dot-separated identifiers left to right.
	# Numeric identifiers compare numerically and rank below alphanumeric ones;
	# a shorter run of identifiers ranks below a longer one that shares its
	# prefix (rc.1 < rc.1.1).
	local -a a_ids b_ids
	IFS=. read -r -a a_ids <<<"$a_pre"
	IFS=. read -r -a b_ids <<<"$b_pre"
	local n=${#a_ids[@]}
	((${#b_ids[@]} > n)) && n=${#b_ids[@]}
	for ((i = 0; i < n; i++)); do
		x="${a_ids[$i]-}"
		y="${b_ids[$i]-}"
		[ -z "$x" ] && {
			echo -1
			return
		}
		[ -z "$y" ] && {
			echo 1
			return
		}
		[ "$x" = "$y" ] && continue
		if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
			((10#$x < 10#$y)) && echo -1 || echo 1
			return
		fi
		if [[ "$x" =~ ^[0-9]+$ ]]; then
			echo -1
			return
		fi
		if [[ "$y" =~ ^[0-9]+$ ]]; then
			echo 1
			return
		fi
		[[ "$x" < "$y" ]] && echo -1 || echo 1
		return
	done
	echo 0
}

# --------------------------------------------------------------------------- #
# Changelog parsing (Keep a Changelog: "## [1.2.3] - 2026-08-18")
# --------------------------------------------------------------------------- #

# Released versions, newest first as they appear in the file. "## [Unreleased]"
# carries no version and is skipped, which is what lets it sit above them.
changelog_versions() {
	sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' "$CHANGELOG"
}

# The " - YYYY-MM-DD" of a section heading, or empty when it has none.
changelog_date() { # <version>
	sed -n "s/^## \[$1\][[:space:]]*-[[:space:]]*\([0-9-]*\).*/\1/p" "$CHANGELOG" | head -n 1
}

# Everything between a section heading and the next "## " heading.
changelog_body() { # <version>
	awk -v want="## [$1]" '
		index($0, want) == 1 { collecting = 1; next }
		collecting && /^## / { exit }
		collecting { print }
	' "$CHANGELOG"
}

# --------------------------------------------------------------------------- #

while [ $# -gt 0 ]; do
	case "$1" in
	--ref)
		REF="${2:-}"
		shift 2
		;;
	--repository)
		REPOSITORY="${2:-}"
		shift 2
		;;
	--changelog)
		CHANGELOG="${2:-}"
		shift 2
		;;
	--notes)
		NOTES="${2:-}"
		shift 2
		;;
	--gomod)
		GOMOD="${2:-}"
		shift 2
		;;
	-h | --help)
		sed -n '2,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) fail "unknown argument: $1" ;;
	esac
done

[ -f "$CHANGELOG" ] || fail "no changelog at ${CHANGELOG}"

# --- 1. The version, from the tag or (dry run) from the changelog -----------
mapfile -t RELEASED < <(changelog_versions)
[ "${#RELEASED[@]}" -gt 0 ] || fail "${CHANGELOG} has no released section (expected '## [X.Y.Z] - YYYY-MM-DD')"

if [ -n "$REF" ]; then
	case "$REF" in
	refs/tags/*) TAG="${REF#refs/tags/}" ;;
	*) fail "--ref must be a tag ref (refs/tags/vX.Y.Z), got: ${REF}" ;;
	esac
	case "$TAG" in
	v*) VERSION="${TAG#v}" ;;
	*) fail "release tags are prefixed with 'v' (expected vX.Y.Z, got ${TAG})" ;;
	esac
else
	VERSION="${RELEASED[0]}"
	TAG="v${VERSION}"
	echo "dry run: no tag; taking the version from the newest changelog section"
fi

semver_valid "$VERSION" || fail "'${VERSION}' is not a semantic version (expected X.Y.Z or X.Y.Z-prerelease)"

MINOR="${VERSION%%-*}"
MINOR="${MINOR%.*}"
PRERELEASE=false
[ "$VERSION" != "${VERSION%%-*}" ] && PRERELEASE=true

# --- 2. The changelog names it, at the top, dated and non-empty -------------
if [ "${RELEASED[0]}" != "$VERSION" ]; then
	if printf '%s\n' "${RELEASED[@]}" | grep -qx -- "$VERSION"; then
		fail "${CHANGELOG} has a section for ${VERSION}, but ${RELEASED[0]} sits above it — the released version must be the newest section"
	fi
	fail "${CHANGELOG} has no section for ${VERSION} (its newest is ${RELEASED[0]}); add '## [${VERSION}] - $(date -u +%Y-%m-%d)' with the release notes"
fi

DATE="$(changelog_date "$VERSION")"
[ -n "$DATE" ] || fail "the ${VERSION} section is undated; use '## [${VERSION}] - YYYY-MM-DD'"
[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "the ${VERSION} section's date '${DATE}' is not YYYY-MM-DD"
date -u -d "$DATE" >/dev/null 2>&1 || fail "the ${VERSION} section's date '${DATE}' is not a real date"

BODY="$(changelog_body "$VERSION")"
if [ -z "$(printf '%s' "$BODY" | tr -d '[:space:]')" ]; then
	fail "the ${VERSION} section is empty — a release with no notes is a release nobody can read"
fi

# --- 3. Released sections descend --------------------------------------------
prev=""
for v in "${RELEASED[@]}"; do
	semver_valid "$v" || fail "${CHANGELOG} has a section '## [${v}]' that is not a semantic version"
	if [ -n "$prev" ] && [ "$(semver_cmp "$prev" "$v")" != "1" ]; then
		fail "${CHANGELOG} lists ${prev} above ${v}; released sections must descend (newest first)"
	fi
	prev="$v"
done

# --- 4. The module path matches the repository -------------------------------
if [ -n "$REPOSITORY" ]; then
	[ -f "$GOMOD" ] || fail "no go.mod at ${GOMOD}"
	MODULE="$(sed -n 's/^module[[:space:]]\{1,\}//p' "$GOMOD" | head -n 1)"
	EXPECTED="github.com/${REPOSITORY}/server"
	[ "$MODULE" = "$EXPECTED" ] ||
		fail "server/go.mod declares module '${MODULE}', but this run is on ${REPOSITORY} (expected '${EXPECTED}'). \`go install\` and the cosign identity both key off that path; fix go.mod or release from the right repository"
fi

# --- Report -------------------------------------------------------------------
if [ -n "$NOTES" ]; then
	{
		printf '%s\n' "$BODY"
	} >"$NOTES"
	echo "release notes -> ${NOTES} ($(wc -l <"$NOTES") lines)"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		echo "version=${VERSION}"
		echo "tag=${TAG}"
		echo "minor=${MINOR}"
		echo "prerelease=${PRERELEASE}"
	} >>"$GITHUB_OUTPUT"
fi

echo "ok: releasing ${TAG}"
echo "    version      ${VERSION}"
echo "    minor line   ${MINOR}"
echo "    pre-release  ${PRERELEASE}"
echo "    dated        ${DATE}"
[ -n "$REPOSITORY" ] && echo "    module       github.com/${REPOSITORY}/server"
exit 0
