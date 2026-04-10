package vpn

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RouteManager handles VPN route setup and teardown using fwmark-based policy routing.
//
// How it works:
// 1. WireGuard device is configured with FwMark (set in wireguard.go)
//   - All encapsulated packets leaving WG get this mark automatically
//
// 2. ip rule: packets WITH fwmark -> use main table (normal routing to VPN server)
// 3. ip rule: packets WITHOUT fwmark -> use VPN table (route through tunnel)
// 4. VPN table has default route through pvpn0
//
// Flow: app packet -> no mark -> VPN table -> pvpn0 -> WG encrypts -> marks packet
//
//	-> main table -> real gateway -> VPN server
type RouteManager struct {
	link  netlink.Link
	rules []*netlink.Rule
}

// NewRouteManager creates a route manager for the given VPN interface.
func NewRouteManager(link netlink.Link) *RouteManager {
	return &RouteManager{link: link}
}

// Up sets up fwmark-based policy routing.
func (rm *RouteManager) Up() error {
	// Clean up any stale rules/routes from a previous session
	cleanupRules()
	cleanupRoutes()

	// Priorities must be between other services (e.g., Tailscale at ~5270)
	// and the default main/default tables (32766/32767).
	const basePriority = 10000

	// Rule 1: Fwmarked packets (WireGuard encapsulated) use main table.
	// This ensures encrypted VPN traffic reaches the server via the real interface.
	fwmarkRule := netlink.NewRule()
	fwmarkRule.Mark = FWMark
	fwmarkRule.Table = 254 // main table
	fwmarkRule.Priority = basePriority
	if err := netlink.RuleAdd(fwmarkRule); err != nil {
		return fmt.Errorf("add fwmark rule: %w", err)
	}
	rm.rules = append(rm.rules, fwmarkRule)

	// Rule 2: All other packets use our custom VPN routing table.
	// This catches all non-WireGuard traffic and routes it through the tunnel.
	vpnRule := netlink.NewRule()
	vpnRule.Invert = true
	vpnRule.Mark = FWMark
	vpnRule.Table = RouteTable
	vpnRule.Priority = basePriority + 1
	if err := netlink.RuleAdd(vpnRule); err != nil {
		rm.Down()
		return fmt.Errorf("add VPN rule: %w", err)
	}
	rm.rules = append(rm.rules, vpnRule)

	// IPv6 rules — route IPv6 into VPN table too (where it hits a blackhole).
	// Without this, IPv6 bypasses the VPN entirely.
	v6VpnRule := netlink.NewRule()
	v6VpnRule.Family = unix.AF_INET6
	v6VpnRule.Invert = true
	v6VpnRule.Mark = FWMark
	v6VpnRule.Table = RouteTable
	v6VpnRule.Priority = basePriority + 1
	if err := netlink.RuleAdd(v6VpnRule); err == nil {
		rm.rules = append(rm.rules, v6VpnRule)
	}

	// Add default route through VPN interface in our custom table
	_, allIPv4, _ := net.ParseCIDR("0.0.0.0/0")
	vpnRoute := &netlink.Route{
		LinkIndex: rm.link.Attrs().Index,
		Dst:       allIPv4,
		Table:     RouteTable,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(vpnRoute); err != nil {
		rm.Down()
		return fmt.Errorf("add VPN default route: %w", err)
	}

	// Blackhole IPv6 in the VPN table — Proton tunnels are IPv4-only.
	// Without this, IPv6 DNS results (AAAA records) cause connections to
	// hang because there's no IPv6 path through the tunnel. The blackhole
	// makes IPv6 fail instantly so apps fall back to IPv4 (happy eyeballs).
	_, allIPv6, _ := net.ParseCIDR("::/0")
	v6Blackhole := &netlink.Route{
		Dst:   allIPv6,
		Table: RouteTable,
		Type:  unix.RTN_BLACKHOLE,
	}
	// Non-fatal — IPv6 just won't fail fast if this errors.
	_ = netlink.RouteAdd(v6Blackhole)

	// Suppress prefixlength rule: prevents packets from leaking via
	// longest-prefix match in the main table when VPN table has no match
	suppressRule := netlink.NewRule()
	suppressRule.SuppressPrefixlen = 0
	suppressRule.Table = 254 // main table
	suppressRule.Priority = basePriority - 1
	if err := netlink.RuleAdd(suppressRule); err != nil {
		// Non-fatal, the fwmark rules handle most cases
	} else {
		rm.rules = append(rm.rules, suppressRule)
	}

	return nil
}

// Down removes all VPN routes and rules.
func (rm *RouteManager) Down() error {
	var firstErr error

	// Remove ip rules
	for _, rule := range rm.rules {
		if err := netlink.RuleDel(rule); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delete rule: %w", err)
		}
	}
	rm.rules = nil

	// Remove VPN routes from custom table
	if rm.link != nil {
		_, allIPv4, _ := net.ParseCIDR("0.0.0.0/0")
		netlink.RouteDel(&netlink.Route{
			LinkIndex: rm.link.Attrs().Index,
			Dst:       allIPv4,
			Table:     RouteTable,
		})
	}
	_, allIPv6, _ := net.ParseCIDR("::/0")
	netlink.RouteDel(&netlink.Route{
		Dst:   allIPv6,
		Table: RouteTable,
		Type:  unix.RTN_BLACKHOLE,
	})

	return firstErr
}
