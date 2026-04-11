package vpn

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

const (
	tableName    = "pvpn_killswitch"
	reconnectSet = "pvpn_reconnect" // named set of pre-resolved Proton API IPs
)

// KillSwitch manages nftables rules that block all non-VPN traffic.
type KillSwitch struct {
	enabled bool
	// lastServerIP / lastAPIIPs are retained so Disable can decide whether
	// to clear the preboot state even when called from a cleanup path that
	// no longer has these values handy.
	lastServerIP net.IP
	lastAPIIPs   []net.IP
}

// NewKillSwitch creates a kill switch manager.
func NewKillSwitch() (*KillSwitch, error) {
	// Verify nft is available
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft not found: %w (is nftables installed?)", err)
	}
	return &KillSwitch{}, nil
}

// Enable activates the kill switch, allowing only VPN and LAN traffic.
// apiIPs must be pre-resolved IPv4 addresses for the Proton API hostname;
// they are seeded into the reconnect set so the daemon can reach the API
// during reconnect without needing DNS (which is tunnel-scoped under the
// kill switch — see F-1 fix).
func (ks *KillSwitch) Enable(serverIP net.IP, apiIPs []net.IP) error {
	// Remove any existing rules first (idempotent)
	ks.Disable()

	rules := buildRules(serverIP)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, string(output))
	}

	// Pre-seed the reconnect set with the resolved API IPs. These must be
	// added AFTER the table exists (buildRules creates the set) but before
	// the daemon ever needs to hit the API while the tunnel is down.
	for _, ip := range apiIPs {
		v4 := ip.To4()
		if v4 == nil {
			continue // set is ipv4_addr only
		}
		nft := fmt.Sprintf("add element inet %s %s { %s }", tableName, reconnectSet, v4.String())
		if out, err := exec.Command("nft", nft).CombinedOutput(); err != nil {
			return fmt.Errorf("seed api IP %s: %w: %s", v4, err, string(out))
		}
	}

	ks.enabled = true
	ks.lastServerIP = serverIP
	ks.lastAPIIPs = apiIPs

	// Persist the kill switch to disk so that the early-boot systemd
	// oneshot can reinstate the same policy on the next reboot BEFORE any
	// network interface comes up (F-3 fix). Best-effort — a failure here
	// does not invalidate the runtime kill switch, so log and continue.
	if err := WritePrebootKillSwitch(serverIP, apiIPs); err != nil {
		log.Printf("kill switch: failed to persist preboot state: %v (runtime kill switch is still active)", err)
	}

	return nil
}

// Disable removes the kill switch rules and clears the persisted preboot
// state so the early-boot oneshot skips on the next reboot. This is called
// both from SetKillSwitch(false) (user explicitly disables) and from the
// full teardown path (normal disconnect with kill switch not preserved).
// During reconnect, teardown keeps the rules in place and does NOT call
// Disable, so the preboot state correctly survives a reconnect cycle.
func (ks *KillSwitch) Disable() error {
	// Delete the table (removes all chains and rules within it)
	cmd := exec.Command("nft", "delete", "table", "inet", tableName)
	cmd.CombinedOutput() // Ignore error (table might not exist)
	ks.enabled = false

	// Clear the preboot state flag so the next reboot does not reinstate
	// the kill switch. The ruleset file is kept on disk for audit.
	if err := ClearPrebootKillSwitch(); err != nil {
		log.Printf("kill switch: failed to clear preboot state: %v", err)
	}
	return nil
}

// IsEnabled returns whether the kill switch is active.
func (ks *KillSwitch) IsEnabled() bool {
	return ks.enabled
}

// Verify checks that the kill switch table is actually present in the
// running nftables ruleset. This catches the class of bugs where the
// daemon thinks the kill switch is on but something removed the table
// out from under us (concurrent connect race, external `nft flush
// ruleset`, OOM killer hit the nft helper mid-setup). Returns nil if
// the table is loaded, an error otherwise.
//
// Called after every successful connect when the user has kill switch
// enabled — a missing table at that point means the daemon state and
// kernel state disagree, and the safest action is to fail the connect
// loudly rather than silently leave the user unprotected.
func VerifyKillSwitch() error {
	cmd := exec.Command("nft", "list", "table", "inet", tableName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill switch table %q not loaded: %w: %s", tableName, err, strings.TrimSpace(string(output)))
	}
	// Sanity check the contents: if `nft list table` succeeds with an
	// empty body the table exists but has no chains, which is just as
	// broken as no table at all.
	if !strings.Contains(string(output), "chain output") {
		return fmt.Errorf("kill switch table %q has no output chain: %s", tableName, string(output))
	}
	// F-16b regression guard: the forward chain must be present too.
	// Pre-F-16 ruleset had only output — container / VM / bridged
	// traffic was forwarded past the kill switch uninspected.
	if !strings.Contains(string(output), "chain forward") {
		return fmt.Errorf("kill switch table %q has no forward chain (F-16 regression — container traffic would bypass kill switch): %s", tableName, string(output))
	}
	if !strings.Contains(string(output), "policy drop") {
		return fmt.Errorf("kill switch table %q output chain is not drop-policy: %s", tableName, string(output))
	}
	return nil
}

// ResolveAPIHosts resolves the host portion of apiBaseURL to its IPv4
// addresses. Called by the connection layer before Enable so the resolved
// IPs can be seeded into the kill switch's reconnect set while DNS is
// still freely available. Returns an error on parse/lookup failure — the
// caller must decide whether to proceed without an API pinhole.
func ResolveAPIHosts(apiBaseURL string) ([]net.IP, error) {
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("empty host in API URL %q", apiBaseURL)
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, v4)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses for %s", host)
	}
	return ips, nil
}

// RefreshAPIIPs adds (or re-adds) the given IPs to the reconnect set while
// the kill switch is live. Used to refresh pinned API endpoints after a
// successful connect, when the tunnel DNS is available and can return the
// current set of Proton API IPs. Safe to call with an empty slice.
func (ks *KillSwitch) RefreshAPIIPs(ips []net.IP) error {
	if !ks.enabled {
		return nil
	}
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		nft := fmt.Sprintf("add element inet %s %s { %s }", tableName, reconnectSet, v4.String())
		if out, err := exec.Command("nft", nft).CombinedOutput(); err != nil {
			return fmt.Errorf("nft add element: %w: %s", err, string(out))
		}
	}
	return nil
}

func buildRules(serverIP net.IP) string {
	return fmt.Sprintf(`table inet %s {
    set %s {
        type ipv4_addr
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Allow loopback
        oifname "lo" accept

        # Allow VPN interface — covers ALL traffic leaving via the tunnel,
        # including in-tunnel DNS to 10.2.0.1. There is deliberately no
        # broad "udp/tcp dport 53 accept" rule: unscoped DNS would leak
        # plaintext queries to the ISP's resolver even with the kill switch
        # engaged (pre-v0.2.1 F-1 finding).
        #
        # "oifname" (string match) is used instead of "oif" (index match)
        # because the runtime kill switch is now installed BEFORE the
        # tunnel interface exists — Step 0 of the connect flow — so it
        # can shield the handshake to the new server IP. "oif" resolves
        # to an interface index at load time and fails with "Interface
        # does not exist" when pvpn0 is not up yet. "oifname" tolerates
        # the absent interface and matches by name once it appears.
        oifname "%s" accept

        # Allow traffic to VPN server (so the underlying WireGuard UDP
        # handshake can reach the endpoint over the real NIC)
        ip daddr %s accept

        # Allow pre-resolved Proton API IPs. Seeded by KillSwitch.Enable
        # before the drop policy takes effect, so reconnect can still fetch
        # a fresh cert without any DNS egress over the real NIC.
        ip daddr @%s accept

        # Allow LAN traffic
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # Allow DHCP lease renewal
        udp dport { 67, 68 } accept
        ip6 daddr fe80::/10 udp dport { 546, 547 } accept

        # NOTE: there is deliberately no "ct state established,related
        # accept" rule. Pre-v0.2.1 had one, but it was unscoped — any TCP
        # socket that existed BEFORE the kill switch went up kept
        # exchanging traffic over the real NIC, defeating the kill switch
        # for mid-session connects (F-2 finding). In-tunnel return traffic
        # is already covered by "oifname pvpn0 accept" above, so we don't
        # need a ct state rule at all.

        # Drop everything else
        drop
    }

    # F-16b fix: forwarded-traffic chain. The output chain above only
    # fires for packets ORIGINATED by the host netns; traffic coming
    # out of a container (Docker, Podman, libvirt/KVM bridge, LXC) is
    # FORWARDED through the host and never touches output. Without
    # this chain, any such forwarded packet bypasses the kill switch
    # entirely and goes wherever routing sends it — and when pvpn0 is
    # momentarily down during a reconnect window, that was observed
    # to be the real NIC, leaking container traffic via the ISP.
    #
    # The rules mirror the output-chain allowlist (minus loopback,
    # which is never forwarded, and minus DHCP, which is never
    # forwarded either), so the forward policy is symmetric with
    # output: egress via pvpn0, or via a legit LAN subnet, or drop.
    chain forward {
        type filter hook forward priority filter; policy drop;

        # Forwarded out the VPN tunnel — the normal path for
        # container/VM internet traffic once everything is healthy.
        oifname "%s" accept

        # Forwarded to the VPN server itself or the reconnect API —
        # rare for forwarded packets but keeps the chain symmetric
        # with the output chain so corner-case router-style setups
        # don't silently break.
        ip daddr %s accept
        ip daddr @%s accept

        # Forwarded to legit LAN ranges. This also covers the
        # common case of container-to-container traffic on a Docker
        # bridge (docker0 is inside 172.16.0.0/12) and libvirt /
        # KVM bridged VMs on 192.168.x.y.
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        drop
    }
}
`, tableName, reconnectSet, InterfaceName, serverIP.String(), reconnectSet, InterfaceName, serverIP.String(), reconnectSet)
}
