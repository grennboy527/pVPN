#!/usr/bin/env bash
#
# pVPN installer — fetches prebuilt binaries from a GitHub release
# and sets up the systemd service and pvpn group.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/install.sh | sudo bash
#
# Pin a specific version:
#   PVPN_VERSION=v0.2.0 curl ... | sudo bash
#
# To build from source instead, see README ("Build from source").

set -euo pipefail

REPO="YourDoritos/pVPN"
BINDIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
GROUP="pvpn"

log()  { printf '\033[1;34m::\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------

if [ "$(uname -s)" != "Linux" ]; then
    die "pVPN only supports Linux (detected: $(uname -s))."
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    *)            die "Unsupported architecture '$ARCH'. Only x86_64 is currently published. Build from source: https://github.com/${REPO}" ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd (systemctl) not found. pVPN requires systemd."
fi

if ! command -v curl >/dev/null 2>&1; then
    die "curl is required but not installed."
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    die "sha256sum is required but not installed (coreutils)."
fi

# Re-exec under sudo if not root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log "Re-running under sudo..."
    exec sudo -E bash "$0" "$@"
fi

# --- resolve version ---------------------------------------------------------

VERSION="${PVPN_VERSION:-}"
if [ -z "$VERSION" ]; then
    log "Looking up latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -oE '"tag_name":\s*"[^"]+"' \
        | sed -E 's/.*"tag_name":\s*"([^"]+)"/\1/' \
        | head -n1)
    if [ -z "$VERSION" ]; then
        die "Could not determine latest release. Set PVPN_VERSION explicitly."
    fi
fi

log "Installing pVPN ${VERSION} for ${ARCH}"

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}"

# --- download & verify -------------------------------------------------------

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"

log "Downloading binaries..."
for bin in pvpn pvpnd pvpnctl; do
    curl -fsSL -o "$bin" "${BASE_URL}/${bin}" || die "Failed to fetch ${bin}"
done

log "Downloading checksums..."
if ! curl -fsSL -o SHA256SUMS "${BASE_URL}/SHA256SUMS"; then
    warn "SHA256SUMS not published for ${VERSION} — skipping checksum verification."
    warn "Consider upgrading to a newer release that publishes checksums."
else
    log "Verifying checksums..."
    sha256sum -c --ignore-missing SHA256SUMS || die "Checksum verification failed."
fi

log "Downloading systemd unit..."
curl -fsSL -o pvpnd.service "${RAW_URL}/dist/pvpnd.service" || die "Failed to fetch pvpnd.service"

# --- install -----------------------------------------------------------------

log "Creating pvpn group (if missing)..."
if ! getent group "$GROUP" >/dev/null; then
    groupadd -r "$GROUP"
fi

# Add the invoking user (if invoked via sudo) to the pvpn group so they
# can talk to the daemon without re-login via newgrp.
INVOKING_USER="${SUDO_USER:-}"
if [ -n "$INVOKING_USER" ] && [ "$INVOKING_USER" != "root" ]; then
    if ! id -nG "$INVOKING_USER" | tr ' ' '\n' | grep -qx "$GROUP"; then
        log "Adding $INVOKING_USER to $GROUP group..."
        usermod -aG "$GROUP" "$INVOKING_USER"
    fi
fi

log "Installing binaries to ${BINDIR}..."
install -Dm755 pvpn    "${BINDIR}/pvpn"
install -Dm755 pvpnd   "${BINDIR}/pvpnd"
install -Dm755 pvpnctl "${BINDIR}/pvpnctl"

log "Installing systemd unit..."
# Rewrite ExecStart to the actual bindir and inject SUDO_USER for the
# invoking user (matches what Makefile and AUR hook do).
if [ -n "$INVOKING_USER" ] && [ "$INVOKING_USER" != "root" ]; then
    sed -e "s|^ExecStart=.*|ExecStart=${BINDIR}/pvpnd|" \
        -e "/^Environment=SUDO_USER=/d" \
        -e "/^\[Service\]/a Environment=SUDO_USER=${INVOKING_USER}" \
        pvpnd.service > "${SERVICE_DIR}/pvpnd.service"
else
    sed -e "s|^ExecStart=.*|ExecStart=${BINDIR}/pvpnd|" \
        pvpnd.service > "${SERVICE_DIR}/pvpnd.service"
fi
chmod 644 "${SERVICE_DIR}/pvpnd.service"

log "Enabling and starting pvpnd..."
systemctl daemon-reload
systemctl enable --now pvpnd

# --- post-install hints ------------------------------------------------------

cat <<EOF

\033[1;32m✓\033[0m pVPN ${VERSION} installed.

Next steps:
  • Open a new shell (or run: newgrp ${GROUP}) to pick up your new group membership.
  • Run: pvpn
    — or —
    pvpnctl status

Binaries: ${BINDIR}/{pvpn,pvpnd,pvpnctl}
Service:  ${SERVICE_DIR}/pvpnd.service
Uninstall:
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/uninstall.sh | sudo bash
EOF
