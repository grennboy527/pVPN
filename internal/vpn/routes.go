package vpn

import (
	"fmt"
	"log"
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
//
// Rule priorities are chosen so that unmarked (app) traffic NEVER
// consults the main routing table. This is the mitigation for
// TunnelVision (CVE-2024-3661) and LocalNet/TunnelCrack (pVPN F-13 /
// F-14): if a rogue DHCP server (or any other attacker-controlled
// mechanism) injects a specific route into the main table, unmarked
// app traffic must not match it before reaching the VPN table.
//
// Order of evaluation (ascending priority):
//
//  1. 9999 — NOT fwmark → VPN_TABLE. Every unmarked packet (i.e. every
//     app packet, before WireGuard encapsulation) is steered into our
//     custom VPN table. VPN table contains only `default dev pvpn0`
//     (and a v6 blackhole), so the packet matches /0 and goes out the
//     tunnel interface. Main is never consulted, so a rogue /1..../32
//     route in main cannot win.
//
//  2. 10000 — fwmark → main. WireGuard-encapsulated packets (marked
//     with FWMark by the kernel WireGuard module) are looked up in
//     main as normal, so they can reach the VPN server via the real
//     NIC's default gateway.
//
// The pre-v0.2.1 config used `table main suppress_prefixlength 0` at
// a lower priority than the NOT-fwmark rule, which consulted main
// FIRST for unmarked packets and only suppressed /0 matches — any
// longer prefix (a TunnelVision-injected /24 for example) won and
// routed around the tunnel. The suppress rule is no longer used.
func (rm *RouteManager) Up() error {
	// Clean up any stale rules/routes from a previous session
	cleanupRules()
	cleanupRoutes()

	// Priorities must be between other services (e.g., Tailscale at ~5270)
	// and the default main/default tables (32766/32767).
	const basePriority = 9999

	// Rule 1 (pri 9999): All unmarked packets use the VPN routing table.
	// This catches every app packet BEFORE main is consulted, which is
	// what closes the TunnelVision / LocalNet leak class.
	vpnRule := netlink.NewRule()
	vpnRule.Invert = true
	vpnRule.Mark = FWMark
	vpnRule.Table = RouteTable
	vpnRule.Priority = basePriority
	if err := netlink.RuleAdd(vpnRule); err != nil {
		return fmt.Errorf("add VPN rule: %w", err)
	}
	rm.rules = append(rm.rules, vpnRule)

	// Rule 2 (pri 10000): Fwmarked packets (WireGuard encapsulated) use
	// main table. Ensures encrypted VPN traffic reaches the server via
	// the real interface.
	fwmarkRule := netlink.NewRule()
	fwmarkRule.Mark = FWMark
	fwmarkRule.Table = 254 // main table
	fwmarkRule.Priority = basePriority + 1
	if err := netlink.RuleAdd(fwmarkRule); err != nil {
		rm.Down()
		return fmt.Errorf("add fwmark rule: %w", err)
	}
	rm.rules = append(rm.rules, fwmarkRule)

	// IPv6 — route all unmarked IPv6 into VPN table (where it hits a
	// blackhole, since Proton tunnels are v4-only). Without this, v6
	// bypasses the VPN entirely via main's v6 default route.
	v6VpnRule := netlink.NewRule()
	v6VpnRule.Family = unix.AF_INET6
	v6VpnRule.Invert = true
	v6VpnRule.Mark = FWMark
	v6VpnRule.Table = RouteTable
	v6VpnRule.Priority = basePriority
	if err := netlink.RuleAdd(v6VpnRule); err != nil {
		// Non-fatal — some kernels / namespaces lack v6. But log so
		// we notice if it regresses on a real target. Pre-v0.2.1 this
		// error was silently dropped.
		log.Printf("routes: IPv6 policy rule add failed (non-fatal, v6 may leak): %v", err)
	} else {
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

	// F-16a backstop: install an `unreachable default` in the VPN
	// table with a high metric so it wins if and only if the real
	// `default dev pvpn0` (metric 0) is gone. When pvpn0 is torn
	// down — WG crash, link flap, kernel purge of a down-interface
	// route, reconnect teardown — the metric-0 pvpn0 default
	// disappears, the metric-9999 unreachable route takes over, and
	// unmarked traffic continues to fail CLOSED inside the VPN table
	// instead of falling through to main.
	//
	// Without this backstop, the policy-routing lookup at priority
	// 9999 (`not fwmark → VPN_TABLE`) fails when VPN_TABLE has no
	// default, and Linux policy routing falls through to the next
	// matching rule. That would route unmarked traffic via main
	// (priority 32766), defeating the entire F-13 / F-14 fix the
	// moment pvpn0 is purged — and in particular, any FORWARDED
	// traffic (Docker/Podman/KVM bridge/LXC container) would leak
	// via the real NIC because the kill switch's output-only chain
	// never inspects forwarded packets. See F-16 in vm-tests/FINDINGS.md.
	//
	// Unreachable routes carry no LinkIndex, so the kernel cannot
	// purge them on an interface-down event. This route persists
	// for the full lifetime of the VPN table.
	unreachableDefault := &netlink.Route{
		Dst:      allIPv4,
		Table:    RouteTable,
		Type:     unix.RTN_UNREACHABLE,
		Priority: unreachableBackstopMetric,
	}
	if err := netlink.RouteAdd(unreachableDefault); err != nil {
		// Non-fatal: the real default is still installed so normal
		// operation works. Log loudly because the fail-closed
		// guarantee is now weakened — a future tunnel flap may leak.
		log.Printf("routes: unreachable v4 default backstop add failed: %v (F-16: forwarded traffic may leak if pvpn0 is torn down)", err)
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

	// Snapshot the main table's non-default routes into the VPN table.
	//
	// This is the counterpart to the TunnelVision fix: because the
	// NOT-fwmark rule at priority 9999 steers every unmarked packet
	// into the VPN table BEFORE main is consulted, the VPN table now
	// needs to contain the legitimate local-network routes that
	// previously lived only in main (LAN subnet, link-scope routes,
	// admin-added statics). Without this, pinging the LAN gateway —
	// or anything else on the local subnet — gets sent out pvpn0 and
	// dropped, breaking "let LAN devices still reach each other while
	// the VPN is up" (which is a baseline user expectation).
	//
	// The snapshot happens ONCE at connect time. Routes added to main
	// AFTER connect (e.g., a rogue DHCP option 121 injected mid-
	// session) are deliberately NOT copied into the VPN table — they
	// stay invisible to unmarked traffic, which is the whole point of
	// the F-13 fix.
	//
	// Default routes (/0) are excluded from the snapshot because the
	// VPN table's own default route (added above) is the one we want
	// to use for internet-bound traffic.
	snapshotLANRoutes(rm.link.Attrs().Index)

	return nil
}

// snapshotLANRoutes copies every non-default route from the main
// routing table into the VPN table, skipping routes that would point
// back into our own tunnel interface. Errors are logged and swallowed —
// a partial snapshot is still better than failing the whole connect.
//
// Kernel-installed routes in main carry Protocol=RTPROT_KERNEL, which
// the netlink API refuses to accept on RTM_NEWROUTE from userspace.
// We rewrite the clone's Protocol to RTPROT_BOOT (the default for
// `ip route add` without an explicit proto), and zero out the kernel
// metric/flags fields so the kernel doesn't misinterpret them.
func snapshotLANRoutes(tunnelIfIndex int) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Printf("routes: snapshot main table: %v (LAN access may not work)", err)
		return
	}
	log.Printf("routes: snapshot listing %d routes from main table", len(routes))
	copied := 0
	for _, r := range routes {
		// Skip default routes — the VPN table's own default (pvpn0)
		// is the one we want unmarked traffic to use.
		if r.Dst == nil || (r.Dst.IP.Equal(net.IPv4zero) && r.Dst.Mask != nil && net.IP(r.Dst.Mask).Equal(net.IPv4zero)) {
			continue
		}
		// Skip anything already pointing at our tunnel interface.
		if r.LinkIndex == tunnelIfIndex {
			continue
		}
		// Clone the route into the VPN table. Rewrite Protocol from
		// RTPROT_KERNEL (which netlink refuses from userspace) to
		// RTPROT_BOOT so the add succeeds.
		cloned := r
		cloned.Table = RouteTable
		if cloned.Protocol == unix.RTPROT_KERNEL {
			cloned.Protocol = unix.RTPROT_BOOT
		}
		if err := netlink.RouteAdd(&cloned); err != nil {
			// Duplicate / already-exists / no-link errors are expected
			// on reconnect paths where the snapshot already happened;
			// log only at a low noise level.
			log.Printf("routes: snapshot copy %v → VPN table: %v (skipping)", r.Dst, err)
			continue
		}
		copied++
		log.Printf("routes: snapshot copied %v dev-idx=%d → VPN table", r.Dst, r.LinkIndex)
	}
	log.Printf("routes: snapshot done (%d routes copied to VPN table)", copied)
}

// RefreshLANSnapshot re-runs the LAN snapshot into the VPN routing
// table. Needed because when the physical NIC goes down (cable pull,
// WiFi switch, NetworkManager reconfig), the kernel automatically
// purges every route pointing at that interface from *every* table —
// including the snapshot we stuffed into the VPN table at connect
// time. When the NIC comes back up, the kernel re-installs routes
// into main only, not into our custom table, so LAN access stays
// broken until the next full reconnect. Calling this method from the
// network-change handler (even when the handshake is still healthy
// and no reconnect is needed) keeps LAN reachability intact across
// link flaps without touching the tunnel itself.
//
// The underlying snapshotLANRoutes is idempotent: RouteAdd on a
// duplicate returns "file exists" and is swallowed with a skip log.
func (rm *RouteManager) RefreshLANSnapshot() {
	if rm == nil || rm.link == nil {
		return
	}
	snapshotLANRoutes(rm.link.Attrs().Index)
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

	// Remove every route in the VPN table (default, v6 blackhole,
	// and the F-13 LAN snapshot copies).
	cleanupRoutes()

	return firstErr
}
