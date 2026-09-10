#!/bin/sh
# GitHub repository setup (maintainer tooling).
#
# Configures the repository's metadata, security features, default branch, and
# branch protection with `gh`. Safe to re-run: every step is idempotent, and
# steps that need a branch to exist on the remote are reported as PENDING
# instead of failing.
#
# Usage:
#   scripts/github-setup.sh                 # everything except visibility
#   scripts/github-setup.sh --public        # also make the repository public
#
# Making a repository public is a one-way door: forks, caches, and archives
# keep the content. That flag is explicit for exactly that reason.

set -eu

REPO="${WPUS_REPO:-wpultimatesecurity/ultimate-security-cli}"
DEFAULT_BRANCH=dev
RELEASE_BRANCH=main
PUBLIC=no
for arg in "$@"; do
	case "$arg" in
	--public) PUBLIC=yes ;;
	-h | --help)
		sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "github-setup: unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

log() { printf '%s\n' "github-setup: $*"; }
pending() { printf '%s\n' "github-setup: PENDING — $*"; }

command -v gh >/dev/null || {
	echo "github-setup: gh is not installed" >&2
	exit 1
}
gh auth status >/dev/null 2>&1 || {
	echo "github-setup: gh is not authenticated (run: gh auth login)" >&2
	exit 1
}

# --- 1. Metadata ------------------------------------------------------------
log "updating description and topics"
gh repo edit "$REPO" \
	--description "Local, read-only WordPress security auditor in Go. 44 checks, file-integrity verification against WordPress.org, risk + coverage scoring, JSON/SARIF for CI and AI agents." \
	--add-topic wordpress \
	--add-topic wordpress-security \
	--add-topic security-audit \
	--add-topic security-scanner \
	--add-topic vulnerability-scanner \
	--add-topic cli \
	--add-topic golang \
	--add-topic devsecops \
	--add-topic sarif \
	--add-topic static-analysis \
	--enable-issues \
	--enable-wiki=false \
	--enable-projects=false \
	--delete-branch-on-merge

# --- 2. Security features ---------------------------------------------------
log "enabling vulnerability alerts and automated security fixes"
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null

# Secret scanning and push protection are free on public repositories and need
# GitHub Advanced Security on private ones, so this can legitimately fail here.
if gh api -X PATCH "repos/$REPO" \
	-f 'security_and_analysis[secret_scanning][status]=enabled' \
	-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' >/dev/null 2>&1; then
	log "secret scanning and push protection enabled"
else
	pending "secret scanning needs a public repository (or GHAS); re-run after publishing"
fi

# --- 3. Actions policy ------------------------------------------------------
# Workflows in this repository pin every action to a commit SHA; the setting
# below makes that a rule rather than a convention, and the default token is
# read-only so a workflow has to ask for the permissions it needs.
log "hardening Actions: SHA-pinned actions, read-only default token"
gh api -X PUT "repos/$REPO/actions/permissions" \
	-F enabled=true -f allowed_actions=all -F sha_pinning_required=true >/dev/null
gh api -X PUT "repos/$REPO/actions/permissions/workflow" \
	-f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null

# Auto-merge is an organization-level toggle; the API accepts the request but
# the effective value stays false while the organization has it disabled.
if [ "$(gh api "repos/$REPO" --jq '.allow_auto_merge')" != "true" ]; then
	if gh api -X PATCH "repos/$REPO" -F allow_auto_merge=true >/dev/null 2>&1 &&
		[ "$(gh api "repos/$REPO" --jq '.allow_auto_merge')" = "true" ]; then
		log "auto-merge enabled"
	else
		pending "auto-merge is disabled by an organization policy (Org settings → Repository → Allow auto-merge)"
	fi
fi
gh api -X PATCH "repos/$REPO" -F allow_update_branch=true >/dev/null

# --- 4. Default branch ------------------------------------------------------
if git ls-remote --exit-code --heads origin "$DEFAULT_BRANCH" >/dev/null 2>&1 ||
	gh api "repos/$REPO/branches/$DEFAULT_BRANCH" >/dev/null 2>&1; then
	log "setting default branch to $DEFAULT_BRANCH"
	gh repo edit "$REPO" --default-branch "$DEFAULT_BRANCH"
else
	pending "push $DEFAULT_BRANCH first:  git push -u origin $DEFAULT_BRANCH"
fi

# --- 5. Branch protection ---------------------------------------------------
# Status-check contexts are job names as GitHub reports them (the matrix
# expands into one check per combination). A name that does not match leaves a
# pull request waiting, so the list is printed for review.
protect() {
	branch="$1"
	if ! gh api "repos/$REPO/branches/$branch" >/dev/null 2>&1; then
		pending "branch $branch does not exist on the remote yet; protection not applied"
		return 0
	fi
	log "protecting $branch (no force pushes, no deletions, CI required)"
	if ! out=$(gh api -X PUT "repos/$REPO/branches/$branch/protection" \
		-H "Accept: application/vnd.github+json" \
		-F 'required_status_checks[strict]=false' \
		-f 'required_status_checks[contexts][]=Test (ubuntu-latest)' \
		-f 'required_status_checks[contexts][]=Test (macos-latest)' \
		-f 'required_status_checks[contexts][]=Fuzz (security-critical parsers)' \
		-f 'required_status_checks[contexts][]=govulncheck' \
		-f 'required_status_checks[contexts][]=Integration (scan of a real WordPress release)' \
		-f 'required_status_checks[contexts][]=Build linux-amd64' \
		-f 'required_status_checks[contexts][]=Build linux-arm64' \
		-f 'required_status_checks[contexts][]=Build darwin-amd64' \
		-f 'required_status_checks[contexts][]=Build darwin-arm64' \
		-F 'enforce_admins=false' \
		-F 'required_pull_request_reviews=' \
		-F 'restrictions=' \
		-F 'allow_force_pushes=false' \
		-F 'allow_deletions=false' 2>&1); then
		case "$out" in
		*"Upgrade to GitHub Pro"* | *"make this repository public"*)
			# Branch protection on a private repository needs a paid plan;
			# on a public one it is free.
			pending "branch protection for $branch needs a public repository (or a paid plan); re-run after publishing"
			;;
		*)
			printf '%s\n' "github-setup: could not protect $branch: $out" >&2
			return 1
			;;
		esac
	fi
}

protect "$DEFAULT_BRANCH"
protect "$RELEASE_BRANCH"

# --- 6. Code scanning -------------------------------------------------------
# CodeQL default setup is free on public repositories and needs GitHub Advanced
# Security on private ones.
if gh api "repos/$REPO/code-scanning/default-setup" >/dev/null 2>&1 &&
	gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=configured -f query_suite=default >/dev/null 2>&1; then
	log "CodeQL default setup enabled"
else
	pending "code scanning needs a public repository (or GHAS); re-run after publishing"
fi

# --- 7. Visibility (explicit) ----------------------------------------------
if [ "$PUBLIC" = yes ]; then
	log "making $REPO public"
	gh repo edit "$REPO" --visibility public --accept-visibility-change-consequences
	log "re-running secret scanning setup for the public repository"
	gh api -X PATCH "repos/$REPO" \
		-f 'security_and_analysis[secret_scanning][status]=enabled' \
		-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' >/dev/null || true
else
	pending "visibility is still private; publish with:  scripts/github-setup.sh --public"
fi

log "done"
