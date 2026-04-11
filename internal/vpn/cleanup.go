package vpn

import (
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/YourDoritos/pvpn/internal/network"
)

// CleanupIfNoTunnel checks if pvpn0 is still alive. If it is (kernel WG),
// the VPN is working fine without us — leave it alone. If pvpn0 is gone
// (stealth userspace WG died with the process), clean up leftover rules.
func CleanupIfNoTunnel() {
	if _, err := netlink.LinkByName(InterfaceName); err == nil {
		// Interface exists — kernel WG VPN is still running, don't touch it
		return
	}
	// Interface is gone but rules may linger — clean up
	ForceCleanup()
}

// ForceCleanup removes any leftover VPN state (interface, routes, rules, nftables, DNS).
// This is a safety net to ensure the host network is never left broken.
//
// It DOES NOT tear down the kill switch nftables table when the preboot
// state flag exists on disk — that table was just loaded by the early-boot
// oneshot unit (pvpn-preboot-killswitch.service) and is actively blocking
// leaks. Deleting it would reopen the exact window the preboot unit was
// built to close. See internal/vpn/preboot.go for the state flag semantics.
//
// When no preboot state exists (e.g. kill switch disabled, or fresh install),
// the stale nft table is deleted as before so a broken previous run does
// not leave a permanent drop-policy table lying around.
func ForceCleanup() {
	// Always revert DNS — even if the interface is already gone.
	// The DirectBackend checks for the backup file on disk, so this works
	// after a hard kill where in-memory state is lost.
	if backend, err := network.DetectBackend(); err == nil {
		backend.RevertDNS(0) // ifIndex doesn't matter for DirectBackend
	}

	// Remove pvpn0 interface if it still exists
	if link, err := netlink.LinkByName(InterfaceName); err == nil {
		netlink.LinkDel(link)
	}

	// Remove ip rules referencing our routing table or fwmark
	cleanupRules()

	// Remove routes from our custom table
	cleanupRoutes()

	// Remove the nftables kill switch table ONLY if the preboot state
	// flag is absent. If it's present, the table we'd be deleting was
	// installed by the preboot unit and must stay up until the daemon
	// takes over with its runtime rules (via Connection.Connect →
	// KillSwitch.Enable), which handles the swap atomically.
	if !prebootStateExists() {
		exec.Command("nft", "delete", "table", "inet", "pvpn_killswitch").Run()
	}
}

// prebootStateExists reports whether the kill switch state flag written
// by WritePrebootKillSwitch is present on disk. Split out so startup
// cleanup can avoid tearing down a table the preboot unit just loaded.
func prebootStateExists() bool {
	_, err := os.Stat(prebootStatePath)
	return err == nil
}

func cleanupRules() {
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return
	}
	for _, r := range rules {
		if ruleIsOurs(&r) {
			netlink.RuleDel(&r)
		}
	}

	// IPv6 rules too
	rules6, err := netlink.RuleList(unix.AF_INET6)
	if err != nil {
		return
	}
	for _, r := range rules6 {
		if ruleIsOurs(&r) {
			netlink.RuleDel(&r)
		}
	}
}

// ruleIsOurs reports whether the given netlink rule was installed by a
// previous pVPN session. We match on:
//   - Table == RouteTable (our custom VPN table)
//   - Mark == FWMark (the WireGuard fwmark)
//   - SuppressPrefixlen == 0 with Table == 254 and Priority == 9999
//     (stale v0.2.0 suppress rule — see F-13 fix notes in routes.go)
//
// The suppress-rule match exists so that upgrading from v0.2.0 to
// v0.2.1 cleans up the old rule on the first daemon start — otherwise
// the old leak-prone priority-9999 rule would coexist with the new
// priority-9999 NOT-fwmark rule and re-introduce the TunnelVision leak.
func ruleIsOurs(r *netlink.Rule) bool {
	if r.Table == RouteTable {
		return true
	}
	if r.Mark == FWMark {
		return true
	}
	// Stale v0.2.0 suppress rule.
	if r.SuppressPrefixlen == 0 && r.Table == 254 && r.Priority == 9999 {
		return true
	}
	return false
}

func cleanupRoutes() {
	// Since the TunnelVision fix (F-13) the VPN table contains more
	// than just the default route — a snapshot of main-table LAN
	// routes gets copied in at connect time so local network access
	// still works. Enumerate and delete everything in the table
	// rather than hard-coding a known list.
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, r := range routes {
			rr := r
			netlink.RouteDel(&rr)
		}
	}
}
