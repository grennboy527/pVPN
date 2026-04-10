# pVPN

A fast, lightweight **Proton VPN client for Linux** with a terminal UI. Written in Go.

Daemon-based architecture — the VPN stays connected when you close the TUI. Works with **NetworkManager**, **systemd-networkd + iwd**, or bare setups — auto-detects your network stack.

Unlike the official Proton VPN Linux app, pVPN:
- **Doesn't require NetworkManager** — works on any network setup
- **Supports Stealth protocol** (WireGuard-over-TLS) — bypasses DPI and firewalls
- **Runs as a lightweight daemon** — no Electron, no Python, just Go binaries

## Features

- Daemon + client architecture (VPN persists when TUI closes)
- Stealth protocol (WireGuard-over-TLS, bypasses DPI/firewalls)
- Smart protocol selection (auto-detect best protocol/port)
- Secure Core multi-hop (route through CH/IS/SE before exit)
- Server filters (Tor, Streaming, P2P, Secure Core toggles)
- Port forwarding with automatic renewal (NAT-PMP)
- Custom DNS (override Proton DNS via config)
- SRP authentication with 2FA
- Session persists across restarts (no re-login)
- Kill switch (nftables)
- NetShield (ad/tracker/malware blocking)
- VPN Accelerator, Moderate NAT
- IPv6 leak prevention

## Requirements

- Linux with systemd
- Kernel 5.6+ (for WireGuard)
- `x86_64` (other architectures: build from source)
- A Proton VPN account (Plus or higher for most servers)

## Install

### One-liner (any Linux distro)

```bash
curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/install.sh | sudo bash
```

This fetches the latest prebuilt binaries from the GitHub release, verifies
checksums, installs the systemd unit, and creates a `pvpn` group so you can
talk to the daemon without `sudo`. Your user is added to the group
automatically — open a new shell (or run `newgrp pvpn`) to pick it up.

Pin a specific version:

```bash
PVPN_VERSION=v0.2.0 curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/install.sh | sudo -E bash
```

### AUR (Arch Linux)

```bash
yay -S pvpn-go
```

The daemon is enabled automatically and the `pvpn` group is created.
Add yourself to the group with `sudo usermod -aG pvpn $USER`, then run `pvpn`.

### Build from source

Requires Go 1.26+ (see `go.mod`).

```bash
git clone https://github.com/YourDoritos/pVPN.git
cd pVPN
sudo make install
sudo groupadd -r pvpn   # unprivileged IPC access
sudo usermod -aG pvpn $USER
sudo systemctl daemon-reload
sudo systemctl enable --now pvpnd
# open a new shell (or: newgrp pvpn)
pvpn
```

### Uninstall

```bash
# One-liner (preserves ~/.config/pvpn by default; add --purge to wipe it)
curl -fsSL https://raw.githubusercontent.com/YourDoritos/pVPN/main/uninstall.sh | sudo bash

# AUR
sudo pacman -Rns pvpn-go

# From source
sudo make uninstall
```

## Build

```bash
make build
```

Produces three binaries: `pvpnd` (daemon), `pvpn` (TUI), `pvpnctl` (CLI).

## Usage

```bash
# Start daemon (if not using systemd)
sudo pvpnd

# Open TUI (no sudo needed)
pvpn

# CLI usage
pvpnctl connect fastest
pvpnctl status
pvpnctl disconnect
```

On first launch the TUI shows a login screen. After login, your session is saved and you go straight to the server list.

### Keybindings

| Key | Action |
|-----|--------|
| `1` | Status tab |
| `2` | Servers tab |
| `3` | Settings tab |
| `Enter` | Select server / connect |
| `d` | Disconnect |
| `/` | Search servers |
| `t` | Toggle Tor filter |
| `s` | Toggle Streaming filter |
| `p` | Toggle P2P filter |
| `c` | Toggle Secure Core filter |
| `Esc` | Back |
| `Ctrl+C` | Quit |

### Settings

Toggle features from the settings tab -- changes apply on next connection:

- **Kill Switch** -- block all traffic if VPN drops
- **VPN Accelerator** -- split TCP for faster throughput
- **Moderate NAT** -- deterministic NAT (useful for gaming/P2P)
- **Port Forwarding** -- get an inbound port (displayed in status tab)
- **NetShield** -- block malware, ads, and trackers at DNS level

Custom DNS can be configured in `~/.config/pvpn/config.toml`:

```toml
[dns]
custom_dns = ["1.1.1.1", "8.8.8.8"]
```

Note: Custom DNS bypasses NetShield ad/tracker blocking.

## How it works

`pvpnd` runs as a systemd service and owns the VPN connection (WireGuard interface, routes, DNS, kill switch, certificate rotation, reconnection). `pvpn` (TUI) and `pvpnctl` (CLI) are unprivileged clients that communicate with the daemon via Unix socket IPC at `/run/pvpn/pvpn.sock`.

1. Authenticates via Proton's SRP protocol
2. Fetches server list and certificates
3. Creates a WireGuard interface (`pvpn0`) via netlink
4. Sets up fwmark-based policy routing (all traffic through tunnel)
5. Connects Local Agent via mTLS to negotiate features
6. Switches DNS to Proton's resolver (or custom DNS if configured)
7. On disconnect: tears everything down in reverse order

## Config

Stored in `~/.config/pvpn/config.toml` (respects `SUDO_USER` for the real home directory).
Session data in `~/.local/share/pvpn/session.enc` (encrypted with machine-id derived key).

## License

GPL-3.0 -- required by ProtonVPN/go-vpn-lib dependency.
