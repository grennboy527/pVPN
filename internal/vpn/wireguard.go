package vpn

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	InterfaceName = "pvpn0"
	// Default WireGuard keepalive interval
	PersistentKeepalive = 25 * time.Second
	// Default internal VPN address assigned by Proton
	DefaultVPNAddress = "10.2.0.2/32"
	// Firewall mark for WireGuard encapsulated packets and policy routing
	FWMark = 51820
	// Custom routing table for VPN traffic
	RouteTable = 51820
)

// WireGuardConfig holds everything needed to bring up a WireGuard tunnel.
type WireGuardConfig struct {
	PrivateKey string // Base64 X25519 private key
	PublicKey  string // Base64 X25519 server public key
	Endpoint   string // Server IP:port
	Address    string // VPN interface address (e.g., "10.2.0.2/32")
}

// WireGuardManager handles WireGuard interface lifecycle via netlink + wgctrl.
type WireGuardManager struct {
	wgClient *wgctrl.Client
	link     netlink.Link
	ifIndex  int
}

// NewWireGuardManager creates a new manager. Requires CAP_NET_ADMIN.
func NewWireGuardManager() (*WireGuardManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client: %w", err)
	}
	return &WireGuardManager{wgClient: client}, nil
}

// Up creates the WireGuard interface, configures it, and brings it up.
func (m *WireGuardManager) Up(cfg *WireGuardConfig) error {
	// Parse keys
	privKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	pubKey, err := wgtypes.ParseKey(cfg.PublicKey)
	if err != nil {
		return fmt.Errorf("parse server public key: %w", err)
	}

	// Parse endpoint
	endpointAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve endpoint: %w", err)
	}

	// Clean up any stale interface from a previous session
	if existing, err := netlink.LinkByName(InterfaceName); err == nil {
		netlink.LinkDel(existing)
	}

	// Create WireGuard interface via netlink
	wgLink := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: InterfaceName}}
	if err := netlink.LinkAdd(wgLink); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}
	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return fmt.Errorf("get created interface: %w", err)
	}
	m.link = link
	m.ifIndex = m.link.Attrs().Index

	// Configure WireGuard (private key, peer, fwmark)
	// FwMark is critical: WireGuard marks its own encapsulated packets with this
	// so policy routing can send them through the real interface (not back into the tunnel).
	keepalive := PersistentKeepalive
	_, allIPv4, _ := net.ParseCIDR("0.0.0.0/0")
	fwmark := FWMark

	wgCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		FirewallMark: &fwmark,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   pubKey,
				Endpoint:                    endpointAddr,
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{*allIPv4},
			},
		},
	}
	if err := m.wgClient.ConfigureDevice(InterfaceName, wgCfg); err != nil {
		m.destroyInterface()
		return fmt.Errorf("configure wireguard: %w", err)
	}

	// Assign IP address
	addr, err := netlink.ParseAddr(cfg.Address)
	if err != nil {
		m.destroyInterface()
		return fmt.Errorf("parse address %s: %w", cfg.Address, err)
	}
	if err := netlink.AddrAdd(m.link, addr); err != nil {
		m.destroyInterface()
		return fmt.Errorf("add address: %w", err)
	}

	// Set MTU (WireGuard default minus overhead)
	if err := netlink.LinkSetMTU(m.link, 1420); err != nil {
		m.destroyInterface()
		return fmt.Errorf("set MTU: %w", err)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(m.link); err != nil {
		m.destroyInterface()
		return fmt.Errorf("bring up interface: %w", err)
	}

	return nil
}

// Down tears down the WireGuard interface.
func (m *WireGuardManager) Down() error {
	return m.destroyInterface()
}

// IfIndex returns the interface index (needed for DNS and route management).
func (m *WireGuardManager) IfIndex() int {
	return m.ifIndex
}

// Link returns the netlink.Link for the WireGuard interface.
func (m *WireGuardManager) Link() netlink.Link {
	return m.link
}

// Stats returns the current WireGuard peer stats (rx/tx bytes, last handshake).
func (m *WireGuardManager) Stats() (*PeerStats, error) {
	dev, err := m.wgClient.Device(InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("get device stats: %w", err)
	}
	if len(dev.Peers) == 0 {
		return nil, fmt.Errorf("no peers configured")
	}
	peer := dev.Peers[0]
	return &PeerStats{
		RxBytes:       peer.ReceiveBytes,
		TxBytes:       peer.TransmitBytes,
		LastHandshake: peer.LastHandshakeTime,
	}, nil
}

// Close releases the wgctrl client.
func (m *WireGuardManager) Close() error {
	return m.wgClient.Close()
}

func (m *WireGuardManager) destroyInterface() error {
	if m.link == nil {
		return nil
	}
	err := netlink.LinkDel(m.link)
	m.link = nil
	m.ifIndex = 0
	return err
}

// PeerStats holds WireGuard peer statistics.
type PeerStats struct {
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

// DecodeWGKey decodes a base64-encoded WireGuard key.
func DecodeWGKey(b64 string) (wgtypes.Key, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("decode base64 key: %w", err)
	}
	if len(raw) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("invalid key length: got %d, want %d", len(raw), wgtypes.KeyLen)
	}
	var key wgtypes.Key
	copy(key[:], raw)
	return key, nil
}
