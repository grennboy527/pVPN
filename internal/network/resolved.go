package network

import (
	"fmt"
	"net"

	"github.com/godbus/dbus/v5"
)

// ResolvedBackend manages DNS via systemd-resolved D-Bus API.
type ResolvedBackend struct {
	conn *dbus.Conn
}

// NewResolvedBackend creates a systemd-resolved DNS backend.
func NewResolvedBackend() (*ResolvedBackend, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system D-Bus: %w", err)
	}
	return &ResolvedBackend{conn: conn}, nil
}

func (b *ResolvedBackend) Name() string {
	return "systemd-resolved"
}

// SetDNS configures DNS servers on the VPN interface via systemd-resolved.
func (b *ResolvedBackend) SetDNS(ifIndex int, servers []net.IP) error {
	obj := b.conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")

	// Build DNS server list: array of (family int32, address []byte)
	type dnsEntry struct {
		Family  int32
		Address []byte
	}
	var dnsServers []dnsEntry
	for _, ip := range servers {
		if v4 := ip.To4(); v4 != nil {
			dnsServers = append(dnsServers, dnsEntry{Family: 2, Address: v4})
		} else {
			dnsServers = append(dnsServers, dnsEntry{Family: 10, Address: ip.To16()})
		}
	}

	// SetLinkDNS
	call := obj.Call("org.freedesktop.resolve1.Manager.SetLinkDNS", 0, int32(ifIndex), dnsServers)
	if call.Err != nil {
		return fmt.Errorf("SetLinkDNS: %w", call.Err)
	}

	// SetLinkDomains — route all DNS through VPN
	type domainEntry struct {
		Domain   string
		RoutOnly bool
	}
	domains := []domainEntry{{".", true}}
	call = obj.Call("org.freedesktop.resolve1.Manager.SetLinkDomains", 0, int32(ifIndex), domains)
	if call.Err != nil {
		return fmt.Errorf("SetLinkDomains: %w", call.Err)
	}

	// SetLinkDefaultRoute — not critical if it fails, log and continue
	_ = obj.Call("org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", 0, int32(ifIndex), true)

	return nil
}

// RevertDNS restores DNS on the given interface.
func (b *ResolvedBackend) RevertDNS(ifIndex int) error {
	obj := b.conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	call := obj.Call("org.freedesktop.resolve1.Manager.RevertLink", 0, int32(ifIndex))
	if call.Err != nil {
		return fmt.Errorf("RevertLink: %w", call.Err)
	}
	return nil
}
