package vpn

import (
	"net"
	"strings"
	"testing"
)

// The kill switch is a thin wrapper around `nft -f -`. We can't (and shouldn't)
// shell out to nft in a unit test, but we can verify that buildRules produces
// a ruleset that:
//   1. Drops by default (the whole point of a kill switch).
//   2. Allows only the specific traffic we intend to allow.
//   3. References the right interface name, table name, and server IP.
//
// A regression here is catastrophic (traffic leaks outside the tunnel), so
// this test asserts on the exact strings the daemon hands to nft.

func TestBuildRules_ContainsServerIP(t *testing.T) {
	ip := net.ParseIP("203.0.113.42")
	rules := buildRules(ip)
	if !strings.Contains(rules, "ip daddr 203.0.113.42 accept") {
		t.Errorf("ruleset does not allow server IP %s:\n%s", ip, rules)
	}
}

func TestBuildRules_ContainsInterfaceName(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	// Must allow traffic OUT the VPN interface (otherwise the tunnel itself
	// would be blocked by the default-drop policy). F-9 regression guard:
	// use `oifname` (string match) instead of `oif` (index match) so the
	// rule can be loaded BEFORE the pvpn0 interface exists at Step 0 of the
	// connect flow.
	wanted := `oifname "` + InterfaceName + `" accept`
	if !strings.Contains(rules, wanted) {
		t.Errorf("ruleset does not allow VPN interface %q:\n%s", InterfaceName, rules)
	}
}

func TestBuildRules_ContainsTableAndSet(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	// The table and set names must match what Disable / Enable / RefreshAPIIPs
	// reference, otherwise those operations will fail at runtime.
	if !strings.Contains(rules, "table inet "+tableName) {
		t.Errorf("ruleset missing table %q:\n%s", tableName, rules)
	}
	if !strings.Contains(rules, "set "+reconnectSet+" {") {
		t.Errorf("ruleset missing reconnect set %q:\n%s", reconnectSet, rules)
	}
	if !strings.Contains(rules, "ip daddr @"+reconnectSet+" accept") {
		t.Errorf("ruleset does not reference reconnect set in output chain:\n%s", rules)
	}
}

func TestBuildRules_DefaultPolicyIsDrop(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	// The kill switch is only a kill switch if the chain defaults to drop.
	// If someone ever flips this to `policy accept` the whole thing becomes
	// a no-op and we leak.
	if !strings.Contains(rules, "policy drop") {
		t.Errorf("output chain policy is not drop:\n%s", rules)
	}
	// Explicit drop at the end of the chain as a safety net.
	if !strings.Contains(rules, "        drop\n") {
		t.Errorf("explicit trailing drop missing:\n%s", rules)
	}
}

func TestBuildRules_AllowsLoopback(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	if !strings.Contains(rules, `oifname "lo" accept`) {
		t.Errorf("ruleset does not allow loopback:\n%s", rules)
	}
}

func TestBuildRules_AllowsRFC1918LAN(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	// LAN ranges must all be present — users on split networks will
	// lose local access otherwise and blame the VPN.
	for _, cidr := range []string{
		"ip daddr 10.0.0.0/8 accept",
		"ip daddr 172.16.0.0/12 accept",
		"ip daddr 192.168.0.0/16 accept",
	} {
		if !strings.Contains(rules, cidr) {
			t.Errorf("ruleset missing LAN rule %q:\n%s", cidr, rules)
		}
	}
}

func TestBuildRules_AllowsDHCP(t *testing.T) {
	rules := buildRules(net.ParseIP("1.2.3.4"))
	// Without DHCP lease renewal allowed, long-running clients lose their
	// IP lease and drop off the network.
	if !strings.Contains(rules, "udp dport { 67, 68 } accept") {
		t.Errorf("ruleset does not allow DHCPv4:\n%s", rules)
	}
	if !strings.Contains(rules, "udp dport { 546, 547 } accept") {
		t.Errorf("ruleset does not allow DHCPv6:\n%s", rules)
	}
}

func TestBuildRules_NoBroadDNSAllow(t *testing.T) {
	// F-1 regression guard. Pre-v0.2.1, the ruleset had unscoped
	// `udp/tcp dport 53 accept` rules that let any local process send
	// plaintext DNS to the ISP's resolver even with the kill switch
	// engaged. DNS must instead flow over the tunnel (covered by
	// `oifname "pvpn0" accept`) with Proton API IPs pre-seeded in the
	// reconnect set for the reconnect path.
	rules := buildRules(net.ParseIP("1.2.3.4"))
	for _, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // doc comments in the ruleset are allowed
		}
		if strings.Contains(line, "dport 53 accept") && !strings.Contains(line, `oifname "`) {
			t.Errorf("ruleset contains unscoped DNS allow %q (F-1 regression):\n%s", line, rules)
		}
	}
}

func TestBuildRules_NoBroadEstablishedAllow(t *testing.T) {
	// F-2 regression guard. Pre-v0.2.1, the ruleset unconditionally
	// accepted `ct state established,related`, which let pre-existing
	// TCP sockets keep exchanging traffic over the real NIC after the
	// kill switch went up. In-tunnel return traffic is already covered
	// by `oif "pvpn0" accept`, so no ct state rule is needed at all.
	rules := buildRules(net.ParseIP("1.2.3.4"))
	for _, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // doc comment in the ruleset is allowed
		}
		if strings.Contains(line, "ct state established") {
			t.Errorf("ruleset contains ct state established accept %q (F-2 regression):\n%s", line, rules)
		}
	}
}

func TestBuildRules_IPv6NoLeak(t *testing.T) {
	// IPv6 leak prevention: the current ruleset is IPv4-only (inet family
	// catches both, default-drop policy blocks v6). We only explicitly allow
	// v6 link-local for DHCPv6. Make sure we DON'T accidentally accept any
	// broader v6 range — that would silently leak v6 traffic outside the
	// tunnel.
	rules := buildRules(net.ParseIP("1.2.3.4"))

	// Explicitly disallowed patterns (would indicate a v6 leak if present).
	forbidden := []string{
		"ip6 daddr ::/0 accept",
		"ip6 nexthdr tcp accept",
	}
	for _, f := range forbidden {
		if strings.Contains(rules, f) {
			t.Errorf("ruleset contains suspicious v6 accept %q:\n%s", f, rules)
		}
	}
}

func TestBuildRules_StableAcrossServerIPs(t *testing.T) {
	// Structural rules (policy, LAN, DNS, DHCP, established) should be
	// identical regardless of which server IP is plugged in. Only the
	// `ip daddr <server>` line should change. This is a sanity check
	// against future refactors that might accidentally bake the IP
	// somewhere it shouldn't be.
	a := buildRules(net.ParseIP("10.11.12.13"))
	b := buildRules(net.ParseIP("203.0.113.254"))

	// Strip the server-IP line from both and expect the rest to match.
	stripServerLine := func(s string) string {
		var out []string
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "ip daddr 10.11.12.13") ||
				strings.Contains(line, "ip daddr 203.0.113.254") {
				continue
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
	if stripServerLine(a) != stripServerLine(b) {
		t.Errorf("ruleset structure differs between server IPs (only the\nserver-IP line should vary)")
	}
}
