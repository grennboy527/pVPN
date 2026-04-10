package network

import (
	"github.com/godbus/dbus/v5"
)

// DetectBackend auto-detects the active network stack and returns
// the appropriate DNS backend.
//
// Detection order:
// 1. NetworkManager (D-Bus: org.freedesktop.NetworkManager)
// 2. systemd-resolved (D-Bus: org.freedesktop.resolve1)
// 3. Direct /etc/resolv.conf manipulation (fallback)
func DetectBackend() (DNSBackend, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// No D-Bus at all — use direct fallback
		return NewDirectBackend(), nil
	}
	// Do NOT close conn — dbus.SystemBus() returns a shared singleton

	// Check NetworkManager
	if isServiceActive(conn, "org.freedesktop.NetworkManager") {
		return NewNMBackend()
	}

	// Check systemd-resolved
	if isServiceActive(conn, "org.freedesktop.resolve1") {
		return NewResolvedBackend()
	}

	// Fallback
	return NewDirectBackend(), nil
}

// isServiceActive checks if a D-Bus service is available and responding.
func isServiceActive(conn *dbus.Conn, service string) bool {
	obj := conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	var names []string
	err := obj.Call("org.freedesktop.DBus.ListNames", 0).Store(&names)
	if err != nil {
		return false
	}
	for _, name := range names {
		if name == service {
			return true
		}
	}
	return false
}
