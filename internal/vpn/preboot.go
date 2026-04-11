package vpn

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Pre-boot kill switch persistence.
//
// The runtime kill switch (KillSwitch.Enable) is installed by pvpnd after
// the daemon starts — too late to catch the boot-window leak documented in
// pre-v0.2.1 finding F-3. To close that window, we persist the same drop
// policy + allow set as a file that a oneshot systemd unit loads before
// any network interface is brought up.
//
// Layout:
//   /var/lib/pvpn/preboot.nft      — nftables ruleset file, loaded by
//                                    pvpn-preboot-killswitch.service via
//                                    `nft -f`.
//   /var/lib/pvpn/killswitch.state — zero-byte marker. Presence means "the
//                                    user had the kill switch enabled on
//                                    the last connect; reinstate at boot".
//
// Both files live in /var/lib so they persist across reboots (unlike /run)
// and are writable only by the daemon (which runs as root).

const (
	prebootDir       = "/var/lib/pvpn"
	prebootRulesPath = "/var/lib/pvpn/preboot.nft"
	prebootStatePath = "/var/lib/pvpn/killswitch.state"
	// apiIPsPath stores the pre-resolved Proton API IPs, one per line,
	// for pvpnd to consume at startup. Used to bypass DNS (which is
	// blocked by the preboot kill switch) on the first API call after
	// reboot — see api.Client.SetPinnedAPIIPs.
	apiIPsPath = "/var/lib/pvpn/api-ips.txt"
)

// WritePrebootKillSwitch persists the current kill switch state so that
// an early-boot systemd oneshot can reinstate the same drop policy before
// the network comes up on the next boot. serverIP is the last-connected
// VPN endpoint; apiIPs are the pre-resolved Proton API addresses.
//
// This function is best-effort: if it fails (eg. /var/lib not writable,
// or /var/lib/pvpn can't be created), it logs via the returned error but
// the runtime kill switch still works. Callers should surface the error
// via the daemon log, not abort the connect.
func WritePrebootKillSwitch(serverIP net.IP, apiIPs []net.IP) error {
	if err := os.MkdirAll(prebootDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", prebootDir, err)
	}

	rules := buildPrebootRules(serverIP, apiIPs)
	if err := writeFileAtomic(prebootRulesPath, []byte(rules), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", prebootRulesPath, err)
	}

	// Write the pre-resolved API IPs in a simple newline-delimited text
	// file that pvpnd reads at startup to pin the HTTP client's resolver.
	// This is the DNS-free path for the first API call after reboot.
	var apiBuf strings.Builder
	apiBuf.WriteString("# pVPN pre-resolved Proton API IPs. Regenerated on every successful\n")
	apiBuf.WriteString("# connect by pvpnd. Consumed at startup to pin the HTTP client's\n")
	apiBuf.WriteString("# resolver so the first API call after reboot does not need DNS.\n")
	for _, ip := range apiIPs {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		apiBuf.WriteString(v4.String())
		apiBuf.WriteByte('\n')
	}
	if err := writeFileAtomic(apiIPsPath, []byte(apiBuf.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", apiIPsPath, err)
	}

	// Touch the state flag to mark the kill switch as "should be on at boot".
	f, err := os.OpenFile(prebootStatePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", prebootStatePath, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", prebootStatePath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", prebootStatePath, err)
	}

	// Sync the parent directory so the rename and the state-flag creation
	// are actually committed to stable storage. Without this, a sudden
	// power-off (or `virsh destroy`) can lose the directory entries even
	// though the file data itself was fsynced by writeFileAtomic — which
	// is the exact failure mode we hit on Ubuntu VM boot-leak tests: the
	// state dir came back after reboot with preboot.nft but no
	// killswitch.state / api-ips.txt, so the early-boot unit skipped and
	// pvpnd fell back to DNS. fsyncing the parent dir fixes it.
	if err := fsyncDir(prebootDir); err != nil {
		return fmt.Errorf("fsync %s: %w", prebootDir, err)
	}

	return nil
}

// fsyncDir opens path as a directory and calls fsync on it, so that the
// directory entries (renames and new-file creations within it) are
// durable across a power loss.
func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// LoadPinnedAPIIPs reads the persisted pre-resolved API IPs from disk.
// Returns an empty slice if the file does not exist (normal on first run
// after a fresh install). Non-fatal on any I/O error.
func LoadPinnedAPIIPs() []string {
	f, err := os.Open(apiIPsPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ips []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// ClearPrebootKillSwitch removes the state flag so the early-boot unit
// skips on the next reboot. The ruleset file is left in place for debug
// inspection — it's harmless without the flag.
func ClearPrebootKillSwitch() error {
	if err := os.Remove(prebootStatePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", prebootStatePath, err)
	}
	return nil
}

// writeFileAtomic writes data to path via a tempfile + rename, so that a
// crash mid-write never leaves a half-written ruleset that nft would
// refuse to parse.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".preboot.nft.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		// Cleanup if rename didn't happen
		os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// buildPrebootRules builds the nftables ruleset loaded by the oneshot
// systemd unit at boot, before any network interface comes up. It
// deliberately MIRRORS the runtime ruleset (buildRules) so there is no
// gap in policy between pre-boot and runtime — pvpnd replaces this table
// with its live version once it has started and connected.
//
// Critical differences from buildRules:
//   - The Proton API IPs are baked directly into the chain (not via a
//     named set), because the preboot unit runs before pvpnd and can't
//     populate a set at runtime. This means the IPs are static until the
//     next successful connect refreshes them.
//   - The last-connected server IP is likewise baked in.
//   - `oif "pvpn0" accept` is kept so that if pvpnd brings the tunnel up
//     later, tunnel traffic is accepted without re-loading the table.
func buildPrebootRules(serverIP net.IP, apiIPs []net.IP) string {
	var apiLines []string
	for _, ip := range apiIPs {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		apiLines = append(apiLines, fmt.Sprintf("        ip daddr %s accept", v4.String()))
	}
	apiBlock := "        # (no pre-resolved API IPs — reconnect will rely on runtime DNS)"
	if len(apiLines) > 0 {
		apiBlock = "        # Pre-resolved Proton API IPs, baked in at last connect\n" + strings.Join(apiLines, "\n")
	}

	serverLine := "        # (no pinned server IP)"
	if serverIP != nil && serverIP.To4() != nil {
		serverLine = fmt.Sprintf("        # Last-connected VPN server IP (fast reconnect path)\n        ip daddr %s accept", serverIP.To4().String())
	}

	return fmt.Sprintf(`# pVPN pre-boot kill switch ruleset.
# Generated by pvpnd on each successful connect; loaded by
# pvpn-preboot-killswitch.service before any network interface comes up.
# pvpnd replaces this table with its runtime version when the daemon
# starts. DO NOT edit by hand — changes will be overwritten on next connect.
#
# Note on "oifname" vs "oif": this file is loaded before the pvpn0 tunnel
# exists. nftables' "oif" resolves to an interface index at load time and
# fails with "Interface does not exist" if the name is unknown. "oifname"
# is a string match that tolerates the interface being absent. Once pvpnd
# brings the tunnel up and replaces this table with its runtime version,
# the runtime uses "oif" for slightly faster matching.

table inet %s {
    chain output {
        type filter hook output priority 0; policy drop;

        # Loopback — always allowed
        oifname "lo" accept

        # Tunnel — accepted if pvpnd has brought pvpn0 up by the time any
        # traffic tries to leave this way. At preboot the interface does
        # not exist yet, so this rule is a no-op; it's kept to document
        # the intent and to match the runtime ruleset's shape.
        oifname "%s" accept

%s

%s

        # LAN ranges
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # DHCPv4 + DHCPv6 lease acquisition (needed for the interface to
        # come up at all on most distros)
        udp dport { 67, 68 } accept
        ip6 daddr fe80::/10 udp dport { 546, 547 } accept

        drop
    }
}
`, tableName, InterfaceName, serverLine, apiBlock)
}
