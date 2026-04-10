#!/usr/bin/env bash
#
# pVPN uninstaller — removes binaries, systemd unit, and pvpn group.
# Handles both installs done via install.sh and via `make install`
# (both land in /usr/local/bin and /etc/systemd/system).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/uninstall.sh | sudo bash
#
# Purge user config and session data as well:
#   curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/uninstall.sh | sudo bash -s -- --purge
#
# The script is idempotent: running it twice, or on a system where pVPN
# was never installed, exits 0 with a "nothing to remove" summary.

set -euo pipefail

BINDIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
GROUP="pvpn"

PURGE=0
for arg in "${@:-}"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        "") : ;;
        *) printf 'unknown flag: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

log()  { printf '\033[1;34m::\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# Refuse if pVPN was installed via AUR — let pacman handle removal.
if command -v pacman >/dev/null 2>&1 && pacman -Qi pvpn-go >/dev/null 2>&1; then
    die "pVPN was installed via the AUR (pvpn-go). Uninstall with: sudo pacman -Rns pvpn-go"
fi

# Re-exec under sudo if not root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log "Re-running under sudo..."
    if [ $PURGE -eq 1 ]; then
        exec sudo -E bash "$0" --purge
    else
        exec sudo -E bash "$0"
    fi
fi

removed_anything=0

# --- stop & disable service --------------------------------------------------

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files pvpnd.service >/dev/null 2>&1 \
       && systemctl list-unit-files pvpnd.service | grep -q '^pvpnd.service'; then
        log "Stopping and disabling pvpnd..."
        systemctl disable --now pvpnd 2>/dev/null || true
        removed_anything=1
    fi
fi

# --- remove files ------------------------------------------------------------

for bin in pvpn pvpnd pvpnctl; do
    if [ -e "${BINDIR}/${bin}" ]; then
        log "Removing ${BINDIR}/${bin}"
        rm -f "${BINDIR}/${bin}"
        removed_anything=1
    fi
done

if [ -e "${SERVICE_DIR}/pvpnd.service" ]; then
    log "Removing ${SERVICE_DIR}/pvpnd.service"
    rm -f "${SERVICE_DIR}/pvpnd.service"
    removed_anything=1
fi

if [ -d "${SERVICE_DIR}/pvpnd.service.d" ]; then
    log "Removing ${SERVICE_DIR}/pvpnd.service.d"
    rm -rf "${SERVICE_DIR}/pvpnd.service.d"
    removed_anything=1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# --- remove group (if empty) -------------------------------------------------

if getent group "$GROUP" >/dev/null; then
    # Check if group has any members
    members=$(getent group "$GROUP" | awk -F: '{print $4}')
    if [ -z "$members" ]; then
        log "Removing empty '${GROUP}' group..."
        groupdel "$GROUP" 2>/dev/null || warn "Could not remove ${GROUP} group"
    else
        warn "Group '${GROUP}' still has members (${members}) — leaving intact."
        warn "Remove manually with: sudo groupdel ${GROUP}"
    fi
fi

# --- purge user data ---------------------------------------------------------

purge_home() {
    local home="$1"
    if [ -d "$home/.config/pvpn" ]; then
        log "Removing $home/.config/pvpn"
        rm -rf "$home/.config/pvpn"
    fi
    if [ -d "$home/.local/share/pvpn" ]; then
        log "Removing $home/.local/share/pvpn"
        rm -rf "$home/.local/share/pvpn"
    fi
}

if [ "$PURGE" -eq 1 ]; then
    log "Purging user config and session data..."
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        sudo_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        [ -n "$sudo_home" ] && purge_home "$sudo_home"
    fi
    # Also scan /home for any other users that may have pVPN state.
    if [ -d /home ]; then
        for h in /home/*; do
            [ -d "$h" ] && purge_home "$h"
        done
    fi
fi

# --- summary -----------------------------------------------------------------

echo ""
if [ $removed_anything -eq 0 ] && [ $PURGE -eq 0 ]; then
    log "Nothing to remove — pVPN does not appear to be installed."
    exit 0
fi

printf '\033[1;32m✓\033[0m pVPN uninstalled.\n\n'
if [ $PURGE -eq 0 ]; then
    cat <<EOF
User config (~/.config/pvpn) and session data (~/.local/share/pvpn)
were preserved. To wipe them too, re-run with --purge:

  curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/uninstall.sh \\
    | sudo bash -s -- --purge
EOF
fi
