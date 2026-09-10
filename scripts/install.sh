#!/bin/sh
# Ultimate Security CLI (wpus) installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/wpultimatesecurity/ultimate-security-cli/main/scripts/install.sh | sh
#   sh install.sh                       # auto-detect latest release
#   WPUS_VERSION=v0.1.0 sh install.sh   # pin a version
#   WPUS_INSTALL_DIR=~/.local/bin sh install.sh
#
# Environment overrides:
#   WPUS_REPO       GitHub repo slug (default wpultimatesecurity/ultimate-security-cli)
#   WPUS_VERSION    release tag (default: latest)
#   WPUS_INSTALL_DIR  target directory (default: first writable of
#                     ~/.local/bin, /usr/local/bin)
#
# The script downloads a release binary, verifies its sha256 checksum,
# and installs it atomically. It never touches unrelated configuration.
#
# For provenance rather than integrity, verify the attestation first:
#   gh attestation verify wpus_<version>_<os>_<arch>.tar.gz \
#     --repo wpultimatesecurity/ultimate-security-cli

set -eu

REPO="${WPUS_REPO:-wpultimatesecurity/ultimate-security-cli}"
VERSION="${WPUS_VERSION:-}"
INSTALL_DIR="${WPUS_INSTALL_DIR:-}"

log()  { printf '%s\n' "wpus-install: $*"; }
err()  { printf '%s\n' "wpus-install: error: $*" >&2; exit 1; }

# --- 1. detect OS -----------------------------------------------------------
os="$(uname -s)"
case "$os" in
    Linux) os_name="linux" ;;
    Darwin) os_name="darwin" ;;
    *) err "unsupported operating system: $os (wpus supports Linux and macOS)" ;;
esac

# --- 2. detect architecture -------------------------------------------------
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64) arch_name="amd64" ;;
    aarch64|arm64) arch_name="arm64" ;;
    *) err "unsupported architecture: $arch (wpus supports amd64 and arm64)" ;;
esac

target="${os_name}-${arch_name}"
log "platform: $target"

# --- 3. resolve version ------------------------------------------------------
if [ -z "$VERSION" ]; then
    log "resolving latest release…"
    latest_url="https://github.com/${REPO}/releases/latest/download/checksums.txt"
    # Discover the tag via the redirect of the latest release page.
    VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" | sed 's|.*/tag/||')"
    [ -n "$VERSION" ] || err "could not determine the latest release; set WPUS_VERSION"
fi
log "version: $VERSION"

# --- 4. choose install directory --------------------------------------------
if [ -z "$INSTALL_DIR" ]; then
    for d in "$HOME/.local/bin" "/usr/local/bin"; do
        if [ -d "$d" ] && [ -w "$d" ]; then INSTALL_DIR="$d"; break; fi
    done
    if [ -z "$INSTALL_DIR" ]; then
        INSTALL_DIR="$HOME/.local/bin"
        log "creating $INSTALL_DIR (add it to your PATH)"
        mkdir -p "$INSTALL_DIR"
    fi
fi
if [ ! -w "$INSTALL_DIR" ]; then
    err "install directory $INSTALL_DIR is not writable; set WPUS_INSTALL_DIR"
fi

# --- 5. download -------------------------------------------------------------
base="https://github.com/${REPO}/releases/download/${VERSION}"
archive="wpus_${VERSION#v}_${os_name}_${arch_name}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log "downloading $archive…"
curl -fsSL --retry 3 -o "$tmp/$archive" "$base/$archive" \
    || err "download failed: $base/$archive"

log "downloading checksums.txt…"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt" \
    || err "download failed: $base/checksums.txt"

# --- 6. verify checksum ------------------------------------------------------
expected="$(grep "$archive" "$tmp/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || err "checksum for $archive not found"

if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
else
    err "need shasum or sha256sum to verify the checksum"
fi
[ "$actual" = "$expected" ] || err "checksum mismatch: expected $expected, got $actual"
log "checksum OK"

# --- 7. install atomically ---------------------------------------------------
tar -xzf "$tmp/$archive" -C "$tmp" wpus
chmod +x "$tmp/wpus"
mv -f "$tmp/wpus" "$INSTALL_DIR/wpus.tmp" && mv -f "$INSTALL_DIR/wpus.tmp" "$INSTALL_DIR/wpus"

log "installed: $INSTALL_DIR/wpus"
"$INSTALL_DIR/wpus" version
log "done — run 'wpus scan' to audit a WordPress site"
