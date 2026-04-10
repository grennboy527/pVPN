package vpn

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

const (
	tableName    = "pvpn_killswitch"
	reconnectSet = "pvpn_reconnect" // named set for temporary API IPs
)

// KillSwitch manages nftables rules that block all non-VPN traffic.
type KillSwitch struct {
	enabled bool
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
func (ks *KillSwitch) Enable(serverIP net.IP) error {
	// Remove any existing rules first (idempotent)
	ks.Disable()

	rules := buildRules(serverIP)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, string(output))
	}

	ks.enabled = true
	return nil
}

// Disable removes the kill switch rules.
func (ks *KillSwitch) Disable() error {
	// Delete the table (removes all chains and rules within it)
	cmd := exec.Command("nft", "delete", "table", "inet", tableName)
	cmd.CombinedOutput() // Ignore error (table might not exist)
	ks.enabled = false
	return nil
}

// IsEnabled returns whether the kill switch is active.
func (ks *KillSwitch) IsEnabled() bool {
	return ks.enabled
}

// AllowAPITraffic resolves the API base URL and temporarily allows traffic to
// those IPs through the kill switch. This lets the daemon fetch a new certificate
// during reconnection without disabling the kill switch entirely.
func (ks *KillSwitch) AllowAPITraffic(apiBaseURL string) error {
	if !ks.enabled {
		return nil
	}

	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return fmt.Errorf("parse API URL: %w", err)
	}
	host := u.Hostname()

	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}

	for _, ip := range ips {
		nft := fmt.Sprintf("add element inet %s %s { %s }", tableName, reconnectSet, ip)
		cmd := exec.Command("nft", nft)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft add element: %w: %s", err, string(out))
		}
	}
	return nil
}

// BlockAPITraffic removes the temporary API IP allowance, restoring the
// kill switch to its strict state.
func (ks *KillSwitch) BlockAPITraffic() {
	if !ks.enabled {
		return
	}
	nft := fmt.Sprintf("flush set inet %s %s", tableName, reconnectSet)
	exec.Command("nft", nft).Run()
}

func buildRules(serverIP net.IP) string {
	return fmt.Sprintf(`table inet %s {
    set %s {
        type ipv4_addr
        flags timeout
        timeout 5m
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Allow loopback
        oif "lo" accept

        # Allow VPN interface
        oif "%s" accept

        # Allow traffic to VPN server (so we can reach it)
        ip daddr %s accept

        # Allow temporary API IPs during reconnection
        ip daddr @%s accept

        # Allow DNS for API hostname resolution during reconnection
        udp dport 53 accept
        tcp dport 53 accept

        # Allow LAN traffic
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # Allow DHCP lease renewal
        udp dport { 67, 68 } accept
        ip6 daddr fe80::/10 udp dport { 546, 547 } accept

        # Allow established connections (for existing sessions)
        ct state established,related accept

        # Drop everything else
        drop
    }
}
`, tableName, reconnectSet, InterfaceName, serverIP.String(), reconnectSet)
}
