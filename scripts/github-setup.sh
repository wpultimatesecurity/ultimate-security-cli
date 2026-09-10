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

# Contributing code to a public repo runs it on a GitHub-hosted runner, so
# approval is required for every external contributor rather than only the
# first-time ones.
if gh api -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
	-f approval_policy=all_external_contributors >/dev/null 2>&1; then
	log "fork pull requests require approval for all external contributors"
else
	pending "fork pull request approval policy could not be set"
fi

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

# --- 5. Branch rulesets -----------------------------------------------------
# Two rulesets, because the rules have different audiences:
#
#   protect-branch-history   deletion + non_fast_forward, NO bypass. Applies to
#                            everyone, including admins: history cannot be
#                            rewritten or deleted by accident.
#   require-ci-checks        required_status_checks, bypassed by organization
#                            admins. Required status checks are enforced on
#                            pushes as well as merges, so without a bypass
#                            actor a maintainer cannot push to the branch at
#                            all (see the push rejection this script was
#                            written to fix). Contributors still cannot merge
#                            a pull request until CI passes.
#
# Note that blocking force pushes (per the GitHub docs) also prevents renaming
# or changing the default branch until protect-branch-history is edited.
CI_CHECKS_JSON='[
          { "context": "Test (ubuntu-latest)" },
          { "context": "Test (macos-latest)" },
          { "context": "Minimum declared Go (ubuntu-latest)" },
          { "context": "Minimum declared Go (macos-latest)" },
          { "context": "Fuzz (security-critical parsers)" },
          { "context": "govulncheck" },
          { "context": "Integration (scan of a real WordPress release)" },
          { "context": "Build linux-amd64" },
          { "context": "Build linux-arm64" },
          { "context": "Build darwin-amd64" },
          { "context": "Build darwin-arm64" }
]'

history_ruleset() {
	cat <<JSON
{
  "name": "protect-branch-history",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/$DEFAULT_BRANCH", "refs/heads/$RELEASE_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [ { "type": "deletion" }, { "type": "non_fast_forward" } ]
}
JSON
}

checks_ruleset() {
	cat <<JSON
{
  "name": "require-ci-checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/$DEFAULT_BRANCH", "refs/heads/$RELEASE_BRANCH"], "exclude": [] } },
  "bypass_actors": [ { "actor_type": "OrganizationAdmin", "bypass_mode": "always" } ],
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": true,
        "required_status_checks": $CI_CHECKS_JSON
      }
    }
  ]
}
JSON
}

tags_ruleset() {
	cat <<JSON
{
  "name": "protect-release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "bypass_actors": [ { "actor_type": "OrganizationAdmin", "bypass_mode": "always" } ],
  "rules": [ { "type": "deletion" }, { "type": "update" } ]
}
JSON
}

apply_ruleset() {
	name="$1"
	body="$(mktemp)"
	"$2" >"$body"
	id="$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null | head -1)"
	if [ -n "$id" ]; then
		log "updating ruleset $name (#$id)"
		gh api -X PUT "repos/$REPO/rulesets/$id" --input "$body" >/dev/null
	else
		log "creating ruleset $name"
		gh api -X POST "repos/$REPO/rulesets" --input "$body" >/dev/null
	fi
	rm -f "$body"
}

if gh api "repos/$REPO/branches/$DEFAULT_BRANCH" >/dev/null 2>&1; then
	apply_ruleset protect-branch-history history_ruleset
	apply_ruleset require-ci-checks checks_ruleset
	apply_ruleset protect-release-tags tags_ruleset
	log "effective rules on $DEFAULT_BRANCH: $(gh api "repos/$REPO/rules/branches/$DEFAULT_BRANCH" --jq '[.[].type] | join(", ")')"
	# The list endpoint omits current_user_can_bypass; read each ruleset.
	bypass="$(gh api "repos/$REPO/rulesets" --jq '.[].id' | while read -r id; do
		gh api "repos/$REPO/rulesets/$id" --jq '"\(.name)=\(.current_user_can_bypass)"'
	done | tr '\n' ' ')"
	log "bypass for the current user: $bypass"
else
	pending "branch $DEFAULT_BRANCH does not exist on the remote yet; no ruleset applied"
fi

# --- 6. Labels --------------------------------------------------------------
# The issue templates reference bug/enhancement, which exist by default; this
# adds the one a security project needs beyond them. Dependabot labels its own
# pull requests (dependencies, github_actions).
if ! gh label list --limit 100 2>/dev/null | grep -q "^security"; then
	log "creating the security label"
	gh label create security --description "Hardening and non-sensitive security work" --color 0E8A16 >/dev/null
fi

# --- 7. Code scanning -------------------------------------------------------
# CodeQL default setup is free on public repositories and needs GitHub Advanced
# Security on private ones.
if gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=configured -f query_suite=default >/dev/null 2>&1; then
	log "CodeQL default setup enabled"
else
	pending "code scanning needs a public repository (or GHAS); re-run after publishing"
fi

# "Secret scanning: non-provider patterns" and "validity checks" are managed by
# the organization's code security configuration, not by the repository: the
# repo-level field accepts the value and silently keeps it disabled. Applying
# the organization's recommended configuration to this repository needs the
# admin:org token scope (or the org UI), so it is reported rather than forced.
if [ "$(gh api "repos/$REPO" --jq '.security_and_analysis.secret_scanning_non_provider_patterns.status' 2>/dev/null)" != "enabled" ]; then
	pending "non-provider secret patterns and validity checks need the organization's code security configuration:"
	pending "  gh auth refresh -h github.com -s admin:org"
	org="${REPO%%/*}"
	config_id="$(gh api "orgs/$org/code-security/configurations" --jq '.[0].id' 2>/dev/null || echo '<id>')"
	repo_id="$(gh api "repos/$REPO" --jq .id 2>/dev/null || echo '<repo id>')"
	pending "  gh api -X POST orgs/$org/code-security/configurations/$config_id/attach -f scope=selected -F selected_repository_ids[]=$repo_id"
	pending "  (or apply it from the organization's Code security settings)"
fi

# Reporters must be able to reach the maintainers privately (SECURITY.md
# points at GitHub's advisory form).
if gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null 2>&1; then
	log "private vulnerability reporting enabled"
else
	pending "private vulnerability reporting could not be enabled"
fi

# --- 8. Visibility (explicit) ----------------------------------------------
visibility="$(gh api "repos/$REPO" --jq '.visibility')"
if [ "$PUBLIC" = yes ] && [ "$visibility" != "public" ]; then
	log "making $REPO public"
	gh repo edit "$REPO" --visibility public --accept-visibility-change-consequences
	visibility=public
fi
if [ "$visibility" = "public" ]; then
	log "repository is public"
else
	pending "visibility is still private; publish with:  scripts/github-setup.sh --public"
fi

log "done"
