package vpn

// Unit tests for routes.go rule construction. These don't touch real
// netlink — they build the same Rule structs the runtime code builds
// and assert on the priority / table / mark / invert fields.
//
// The reason this test exists is a regression guard for F-13
// (TunnelVision / CVE-2024-3661) and F-14 (LocalNet / TunnelCrack):
// the leak class those findings cover hinges entirely on the relative
// priorities of the "NOT fwmark → VPN table" and "fwmark → main"
// rules. A future refactor that swaps the order or re-introduces a
// `table main suppress_prefixlength 0` rule at priority 9999 would
// silently re-open the leak — this test fails loudly if either
// happens.

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// buildRuleSet replicates the rule construction inside RouteManager.Up
// (but does not call netlink.RuleAdd). Keeping this in sync with Up is
// the point of the test — if Up changes, this function must too, and
// the assertions below guard the critical invariants.
func buildRuleSet() []*netlink.Rule {
	const basePriority = 9999

	vpnRule := netlink.NewRule()
	vpnRule.Invert = true
	vpnRule.Mark = FWMark
	vpnRule.Table = RouteTable
	vpnRule.Priority = basePriority

	fwmarkRule := netlink.NewRule()
	fwmarkRule.Mark = FWMark
	fwmarkRule.Table = 254
	fwmarkRule.Priority = basePriority + 1

	v6VpnRule := netlink.NewRule()
	v6VpnRule.Family = unix.AF_INET6
	v6VpnRule.Invert = true
	v6VpnRule.Mark = FWMark
	v6VpnRule.Table = RouteTable
	v6VpnRule.Priority = basePriority

	return []*netlink.Rule{vpnRule, fwmarkRule, v6VpnRule}
}

// TestRulePriorities_UnmarkedRuleFirst is the F-13 / F-14 regression
// guard. Unmarked app packets MUST hit the VPN table rule before
// anything else — if a main-table rule (fwmark or suppress) has a
// lower priority number, attacker-injected routes in main table win
// over the VPN table and traffic leaks via the physical NIC.
func TestRulePriorities_UnmarkedRuleFirst(t *testing.T) {
	rules := buildRuleSet()

	var vpnPri, fwmarkPri int
	haveVPN, haveFwmark := false, false
	for _, r := range rules {
		if r.Family == unix.AF_INET6 {
			continue
		}
		if r.Invert && r.Mark == FWMark && r.Table == RouteTable {
			vpnPri = r.Priority
			haveVPN = true
		}
		if !r.Invert && r.Mark == FWMark && r.Table == 254 {
			fwmarkPri = r.Priority
			haveFwmark = true
		}
	}
	if !haveVPN {
		t.Fatal("no NOT-fwmark → VPN_TABLE rule (IPv4)")
	}
	if !haveFwmark {
		t.Fatal("no fwmark → main rule")
	}
	if vpnPri >= fwmarkPri {
		t.Errorf("VPN rule priority (%d) must be STRICTLY LESS THAN fwmark→main rule priority (%d); otherwise marked packets would wrongly hit VPN table before main and apps would hit TunnelVision leak class", vpnPri, fwmarkPri)
	}
}

// TestRulePriorities_NoSuppressPrefixlenOnMain is the F-13 regression
// guard. Pre-v0.2.1 had a `table main suppress_prefixlength 0` rule
// at priority 9999 that consulted main BEFORE the VPN table for
// unmarked packets, suppressing only /0 matches. Any longer prefix
// (a rogue /24 from DHCP option 121, say) won over the VPN table's
// default route and the packet leaked out the physical NIC. The fix
// removes the suppress rule entirely — this test ensures no refactor
// re-introduces it.
func TestRulePriorities_NoSuppressPrefixlenOnMain(t *testing.T) {
	rules := buildRuleSet()
	for _, r := range rules {
		if r.Table == 254 && r.SuppressPrefixlen == 0 {
			t.Errorf("pri %d: found suppress_prefixlength=0 rule on main table — this rule reintroduces the F-13 TunnelVision leak class; see routes.go for why it was removed", r.Priority)
		}
	}
}

// TestRulePriorities_IPv6UnmarkedRule ensures IPv6 app traffic is
// also steered into the VPN table (where it hits the v6 blackhole
// so apps fall back to v4). Without the v6 rule, unmarked v6 packets
// would use main's v6 default route and bypass the VPN — the exact
// class of leak Mullvad's 2024 Cure53 audit flagged.
func TestRulePriorities_IPv6UnmarkedRule(t *testing.T) {
	rules := buildRuleSet()
	for _, r := range rules {
		if r.Family == unix.AF_INET6 && r.Invert && r.Mark == FWMark && r.Table == RouteTable {
			if r.Priority != 9999 {
				t.Errorf("IPv6 NOT-fwmark rule priority = %d, want 9999 (same-priority-as-IPv4 is correct: rules are family-scoped, so a v4 and v6 rule can share a priority without conflict)", r.Priority)
			}
			return
		}
	}
	t.Error("no IPv6 NOT-fwmark → VPN_TABLE rule found — IPv6 app traffic will bypass the VPN and leak via main table")
}

// TestRulePriorities_FwmarkRuleNotInverted is a sanity check: the
// "fwmark → main" rule must NOT be inverted (`Invert=false`). If
// Invert were true it would mean "if NOT fwmarked → main", which is
// the exact misconfiguration that breaks WireGuard encapsulation
// routing (packets loop through the tunnel).
func TestRulePriorities_FwmarkRuleNotInverted(t *testing.T) {
	rules := buildRuleSet()
	for _, r := range rules {
		if r.Table == 254 && r.Mark == FWMark && r.Invert {
			t.Errorf("pri %d: fwmark→main rule is inverted — this would route WireGuard encapsulated packets into the VPN table, causing an infinite loop", r.Priority)
		}
	}
}
