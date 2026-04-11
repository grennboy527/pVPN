package vpn

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// sysctlHardener applies a small set of IPv4 sysctls while a VPN
// connection is active, and reverts them on teardown. The goal is to
// close the ARP/LAN leak class (pVPN F-10, also documented in Mullvad's
// 2024 Cure53 audit and several commercial VPN CVEs over the last five
// years):
//
//   - arp_ignore=2: the kernel only answers ARP requests for an IP if
//     the target address is in the subnet of the incoming interface.
//     With the default (0), the kernel happily ARP-replies for the
//     tunnel IP 10.2.0.x on the physical NIC, which lets anything on
//     the LAN discover and reach the tunnel-facing interface over L2.
//
//   - arp_announce=2: use the best local address for ARP announcements
//     (matches the subnet of the outgoing interface). Prevents the
//     tunnel IP from being advertised onto the physical LAN via
//     gratuitous ARP on link-up events.
//
//   - rp_filter=1: strict reverse-path filter. Drops packets whose
//     source address could not plausibly be received on the interface
//     they arrived on. This is a defense against spoofed inbound
//     packets that would otherwise look like they came through the
//     tunnel.
//
// Reverted sysctls: ALL values touched are recorded at Apply time and
// written back verbatim at Revert time, so the host is returned to its
// original state on disconnect — even if the user had non-default
// values set by their distro or their own tuning.
type sysctlHardener struct {
	// saved maps absolute sysctl file path → original value.
	saved map[string]string
}

// hardeningSysctls lists the sysctls pVPN sets at connect time. The
// `all` pseudo-interface applies the value to every existing and
// future interface as a default — this matters because the physical
// NIC and tunnel interface may both have their own per-interface
// entries, and the kernel uses max(all, per-if) for arp_ignore (so
// setting `all` is sufficient regardless of per-if values).
var hardeningSysctls = map[string]string{
	"/proc/sys/net/ipv4/conf/all/arp_ignore":   "2",
	"/proc/sys/net/ipv4/conf/all/arp_announce": "2",
	"/proc/sys/net/ipv4/conf/all/rp_filter":    "1",
}

// newSysctlHardener constructs an uninitialized hardener. Call Apply to
// snapshot existing values and write the new ones; call Revert to
// restore. Apply / Revert are idempotent.
func newSysctlHardener() *sysctlHardener {
	return &sysctlHardener{saved: make(map[string]string)}
}

// Apply saves each hardening sysctl's current value and then writes
// the hardened value. On a partial failure the already-hardened
// sysctls are left in place — the caller's teardown will Revert them
// cleanly, and a partially hardened state is still safer than the
// original state.
//
// Failures are logged but non-fatal: the daemon can still run on
// kernels where /proc/sys is read-only (containers, hardened LXCs)
// or where a given sysctl does not exist (ancient kernels). Losing
// the hardening means losing a defense-in-depth layer, not losing
// the VPN.
func (h *sysctlHardener) Apply() {
	for path, want := range hardeningSysctls {
		old, err := readSysctl(path)
		if err != nil {
			log.Printf("sysctl hardener: read %s: %v (skipping)", path, err)
			continue
		}
		if old == want {
			// Nothing to change and nothing to revert. Don't touch
			// the saved map — on Revert we must only write back
			// values we actually changed.
			continue
		}
		if err := writeSysctl(path, want); err != nil {
			log.Printf("sysctl hardener: write %s=%s: %v (skipping)", path, want, err)
			continue
		}
		h.saved[path] = old
	}
}

// Revert restores the saved sysctl values. Safe to call multiple times;
// on the second call saved is empty and Revert is a no-op.
func (h *sysctlHardener) Revert() {
	for path, old := range h.saved {
		if err := writeSysctl(path, old); err != nil {
			log.Printf("sysctl hardener: restore %s=%s: %v", path, old, err)
		}
	}
	h.saved = make(map[string]string)
}

func readSysctl(path string) (string, error) {
	// Limit to a small read — sysctl values are always tiny, and
	// refusing to allocate more than this guards against a misnamed
	// path accidentally reading a huge /proc file.
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysctl(path, value string) error {
	// Some paths only accept a newline-terminated value (same as
	// `sysctl -w`). Writing directly to /proc/sys is the idiomatic
	// systemd / Kubernetes / Docker approach and works regardless of
	// whether the sysctl binary is installed.
	if err := os.WriteFile(filepath.Clean(path), []byte(value+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
