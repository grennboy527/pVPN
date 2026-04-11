package vpn

import (
	"net"
	"strings"
	"testing"
)

// The preboot ruleset is loaded by the early-boot oneshot systemd unit
// BEFORE any network interface is brought up. A bug here leaks traffic
// for the entire pre-pvpnd window on every reboot, so the structure is
// covered by the same kind of string assertions as buildRules.

func TestBuildPrebootRules_DefaultPolicyIsDrop(t *testing.T) {
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), []net.IP{net.ParseIP("5.6.7.8")})
	if !strings.Contains(rules, "policy drop") {
		t.Errorf("preboot ruleset has no drop policy:\n%s", rules)
	}
	if !strings.Contains(rules, "        drop\n") {
		t.Errorf("preboot ruleset has no explicit trailing drop:\n%s", rules)
	}
}

func TestBuildPrebootRules_ContainsTable(t *testing.T) {
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), nil)
	if !strings.Contains(rules, "table inet "+tableName) {
		t.Errorf("preboot ruleset missing table %q:\n%s", tableName, rules)
	}
}

func TestBuildPrebootRules_BakesInAPIIPs(t *testing.T) {
	apiIPs := []net.IP{
		net.ParseIP("185.159.159.148"),
		net.ParseIP("185.159.158.10"),
	}
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), apiIPs)
	for _, ip := range apiIPs {
		wanted := "ip daddr " + ip.String() + " accept"
		if !strings.Contains(rules, wanted) {
			t.Errorf("preboot ruleset missing API IP %s:\n%s", ip, rules)
		}
	}
}

func TestBuildPrebootRules_BakesInServerIP(t *testing.T) {
	rules := buildPrebootRules(net.ParseIP("203.0.113.42"), nil)
	if !strings.Contains(rules, "ip daddr 203.0.113.42 accept") {
		t.Errorf("preboot ruleset missing pinned server IP:\n%s", rules)
	}
}

func TestBuildPrebootRules_NoSetReference(t *testing.T) {
	// Preboot runs before pvpnd, so we can't populate a named set at
	// runtime. All allow targets must be baked into the chain directly.
	// This guards against accidentally re-using buildRules' set reference.
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), []net.IP{net.ParseIP("5.6.7.8")})
	if strings.Contains(rules, "@"+reconnectSet) {
		t.Errorf("preboot ruleset references runtime-only set %q:\n%s", reconnectSet, rules)
	}
}

func TestBuildPrebootRules_AllowsLoopbackAndLAN(t *testing.T) {
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), nil)
	required := []string{
		`oifname "lo" accept`,
		"ip daddr 10.0.0.0/8 accept",
		"ip daddr 172.16.0.0/12 accept",
		"ip daddr 192.168.0.0/16 accept",
		"udp dport { 67, 68 } accept",
	}
	for _, r := range required {
		if !strings.Contains(rules, r) {
			t.Errorf("preboot ruleset missing %q:\n%s", r, rules)
		}
	}
}

func TestBuildPrebootRules_UsesOifname(t *testing.T) {
	// Regression guard: preboot runs before pvpn0 exists, and nftables'
	// "oif" resolves to an ifindex at load time — it fails with
	// "Interface does not exist" if the interface is missing. "oifname"
	// is a string match that tolerates missing interfaces. Do NOT change
	// this to "oif" without also ensuring the interface is created first.
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), nil)
	for _, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Match "oif " but not "oifname " — note the trailing space on
		// "oif " so we don't match "oifname".
		if strings.Contains(line, "oif \"") && !strings.Contains(line, "oifname") {
			t.Errorf("preboot ruleset uses oif (fails at preboot if iface missing): %q\n%s", line, rules)
		}
	}
}

func TestBuildPrebootRules_NoBroadDNSOrEstablished(t *testing.T) {
	// Same F-1 / F-2 rules as the runtime ruleset.
	rules := buildPrebootRules(net.ParseIP("1.2.3.4"), nil)
	for _, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "dport 53 accept") && !strings.Contains(line, `oif "`) {
			t.Errorf("preboot ruleset has unscoped DNS allow: %q\n%s", line, rules)
		}
		if strings.Contains(line, "ct state established") {
			t.Errorf("preboot ruleset has ct state established allow: %q\n%s", line, rules)
		}
	}
}
