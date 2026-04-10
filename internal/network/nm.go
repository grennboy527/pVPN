package network

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/godbus/dbus/v5"
)

// NMBackend manages DNS via NetworkManager's D-Bus API.
// When systemd-resolved is also running, DNS is set via resolved (preferred).
// Otherwise uses NM's conf.d global DNS override.
type NMBackend struct {
	conn      *dbus.Conn
	resolved  bool
	usedConfD bool // whether we wrote a conf.d snippet
}

func NewNMBackend() (*NMBackend, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system D-Bus: %w", err)
	}
	resolved := isServiceActive(conn, "org.freedesktop.resolve1")
	return &NMBackend{conn: conn, resolved: resolved}, nil
}

func (b *NMBackend) Name() string {
	if b.resolved {
		return "NetworkManager (via systemd-resolved)"
	}
	return "NetworkManager (D-Bus)"
}

func (b *NMBackend) SetDNS(ifIndex int, servers []net.IP) error {
	if b.resolved {
		return b.setDNSViaResolved(ifIndex, servers)
	}
	return b.setDNSViaConfD(servers)
}

func (b *NMBackend) RevertDNS(ifIndex int) error {
	if b.resolved {
		return b.revertDNSViaResolved(ifIndex)
	}
	// Always try conf.d revert — the file may exist from a previous
	// daemon instance even if usedConfD is false (in-memory state lost).
	return b.revertConfD()
}

// --- systemd-resolved path (preferred, works everywhere resolved runs) ---

func (b *NMBackend) setDNSViaResolved(ifIndex int, servers []net.IP) error {
	obj := b.conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")

	type dnsEntry struct {
		Family  int32
		Address []byte
	}
	var entries []dnsEntry
	for _, ip := range servers {
		if v4 := ip.To4(); v4 != nil {
			entries = append(entries, dnsEntry{Family: 2, Address: v4})
		} else {
			entries = append(entries, dnsEntry{Family: 10, Address: ip.To16()})
		}
	}

	if err := obj.Call("org.freedesktop.resolve1.Manager.SetLinkDNS", 0, int32(ifIndex), entries).Err; err != nil {
		return fmt.Errorf("SetLinkDNS: %w", err)
	}

	type domainEntry struct {
		Domain   string
		RoutOnly bool
	}
	if err := obj.Call("org.freedesktop.resolve1.Manager.SetLinkDomains", 0,
		int32(ifIndex), []domainEntry{{".", true}}).Err; err != nil {
		return fmt.Errorf("SetLinkDomains: %w", err)
	}

	// SetLinkDefaultRoute — makes resolved prefer this link for all DNS
	obj.Call("org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", 0, int32(ifIndex), true)

	// Flush caches so the new DNS is used immediately
	obj.Call("org.freedesktop.resolve1.Manager.FlushCaches", 0)

	return nil
}

func (b *NMBackend) revertDNSViaResolved(ifIndex int) error {
	obj := b.conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	if err := obj.Call("org.freedesktop.resolve1.Manager.RevertLink", 0, int32(ifIndex)).Err; err != nil {
		return fmt.Errorf("RevertLink: %w", err)
	}
	return nil
}

// --- NM conf.d path (when resolved is not available) ---

func (b *NMBackend) setDNSViaConfD(servers []net.IP) error {
	// Check if another service owns resolv.conf — if so, the conf.d
	// approach won't work (they'll overwrite). Skip DNS and warn.
	if owner := resolvConfOwner(); owner != "" {
		// DNS won't be set to Proton's servers, but the VPN tunnel
		// still works — traffic is routed through the VPN. DNS queries
		// to 10.2.0.1 work through the tunnel regardless.
		log.Printf("warning: DNS managed by %s — VPN DNS override skipped. VPN tunnel is active; for Proton DNS (NetShield etc.) consider enabling systemd-resolved.", owner)
		return nil
	}

	conf := "[global-dns-domain-*]\nservers="
	for i, ip := range servers {
		if i > 0 {
			conf += ","
		}
		conf += ip.String()
	}
	conf += "\n"

	if err := writeFileAtomic("/etc/NetworkManager/conf.d/pvpn-dns.conf", []byte(conf), 0644); err != nil {
		return fmt.Errorf("write NM DNS config: %w", err)
	}
	b.usedConfD = true

	nm := b.conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	if err := nm.Call("org.freedesktop.NetworkManager.Reload", 0, uint32(0)).Err; err != nil {
		return fmt.Errorf("reload NM: %w", err)
	}

	return nil
}

func (b *NMBackend) revertConfD() error {
	const confPath = "/etc/NetworkManager/conf.d/pvpn-dns.conf"

	// Check if our config file exists — if not, nothing to revert
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return nil
	}

	if err := removeIfExists(confPath); err != nil {
		return fmt.Errorf("remove NM DNS config: %w", err)
	}

	nm := b.conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	nm.Call("org.freedesktop.NetworkManager.Reload", 0, uint32(0))

	b.usedConfD = false
	return nil
}
