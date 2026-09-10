#!/bin/sh
# End-to-end proof of the integrity path against the real WordPress.org
# checksum service: a pristine release must verify clean, and a tampered core
# file must be detected with its exact path.
#
# This is the only test that needs the network, so it is not part of
# `make test`. Run it with `make integration`, and in CI after a change to the
# checksum, integrity, layout, or report code.
#
# Environment:
#   WPUS_IT_WP_VERSION  WordPress version to download (default 6.4.1)
#
# Requirements: Go, curl, tar, python3.

set -eu

cd "$(dirname "$0")/.."

WP_VERSION="${WPUS_IT_WP_VERSION:-6.4.1}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

log() { printf '%s\n' "integration: $*"; }

log "building wpus"
go build -o "$work/wpus" ./cmd/wpus

log "downloading WordPress $WP_VERSION"
curl -fsSL -o "$work/wp.tar.gz" "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz"
tar -xzf "$work/wp.tar.gz" -C "$work"
cp "$work/wordpress/wp-config-sample.php" "$work/wordpress/wp-config.php"

log "scanning a pristine release"
"$work/wpus" scan "$work/wordpress" --no-config --format json > "$work/clean.json"
python3 - "$work/clean.json" <<'PY'
import json, sys

report = json.load(open(sys.argv[1]))
site = report["sites"][0]
findings = {f["id"]: f for f in site["findings"]}
for check in ("CORE_INTEGRITY_MODIFIED", "CORE_FILE_MISSING", "CORE_UNEXPECTED_FILE"):
    assert findings[check]["status"] == "passed", (check, findings[check])
assert site["coverage_score"] > 0, site["coverage_score"]
print("integration: pristine release verified against the WordPress.org manifest")
PY

log "tampering with a core file"
printf '\n<?php // tampered\n' >> "$work/wordpress/wp-includes/load.php"
"$work/wpus" scan "$work/wordpress" --no-config --format json > "$work/tampered.json"
python3 - "$work/tampered.json" <<'PY'
import json, sys

report = json.load(open(sys.argv[1]))
findings = {f["id"]: f for f in report["sites"][0]["findings"]}
found = findings["CORE_INTEGRITY_MODIFIED"]
assert found["status"] == "failed", found
locations = [o.get("location") for o in found.get("occurrences", [])]
assert "wp-includes/load.php" in locations, locations
print("integration: tampering detected with the exact path")
PY

log "ok"
