package vpn

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/network"
	"github.com/YourDoritos/pvpn/internal/stealth"
	"github.com/vishvananda/netlink"
)

// State represents the VPN connection state.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateDisconnecting
	StateReconnecting
	StateError
)

func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDisconnecting:
		return "Disconnecting"
	case StateReconnecting:
		return "Reconnecting"
	case StateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// ConnectionInfo holds details about the active connection.
type ConnectionInfo struct {
	ServerName    string
	ServerIP      string
	ServerCountry string
	EntryCountry  string // Non-empty for Secure Core connections
	ConnectedAt   time.Time
	State         State
	ForwardedPort uint16
	LastError     error
}

// Connection manages the full VPN connection lifecycle.
type Connection struct {
	mu sync.RWMutex

	client     *api.Client
	dnsBackend network.DNSBackend

	wg         *WireGuardManager
	stealthMgr *stealth.StealthManager
	routes     *RouteManager
	ks         *KillSwitch
	la         *LocalAgent
	portFwd    *PortForwarder
	sysctl     *sysctlHardener // F-10: ARP/LAN leak defenses
	info       ConnectionInfo
	protocol   string // "wireguard" or "stealth"
	onState    func(State)
	onLog      func(string)

	// Reconnection state
	reconnect       bool
	reconnectCancel context.CancelFunc
	lastServer      *api.LogicalServer
	lastCertFeats   api.CertificateFeatures
	lastKillSwitch  bool
	lastProtocol    string
	lastCustomDNS   []string

	// Wake channel — poked by daemon on system resume to skip backoff
	wakeCh chan struct{}
}

// tunnelLink returns the netlink.Link for whichever tunnel is active.
func (c *Connection) tunnelLink() netlink.Link {
	if c.stealthMgr != nil {
		return c.stealthMgr.Link()
	}
	if c.wg != nil {
		return c.wg.Link()
	}
	return nil
}

// tunnelIfIndex returns the interface index for whichever tunnel is active.
func (c *Connection) tunnelIfIndex() int {
	if c.stealthMgr != nil {
		return c.stealthMgr.IfIndex()
	}
	if c.wg != nil {
		return c.wg.IfIndex()
	}
	return 0
}

// NewConnection creates a new VPN connection manager.
func NewConnection(client *api.Client, dnsBackend network.DNSBackend) *Connection {
	return &Connection{
		client:     client,
		dnsBackend: dnsBackend,
		info:       ConnectionInfo{State: StateDisconnected},
		wakeCh:     make(chan struct{}, 1),
	}
}

// OnStateChange registers a callback for state changes.
func (c *Connection) OnStateChange(fn func(State)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onState = fn
}

// OnLog registers a callback for log messages (from Local Agent etc.).
func (c *Connection) OnLog(fn func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onLog = fn
}

// Info returns the current connection info.
func (c *Connection) Info() ConnectionInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.info
}

// State returns the current connection state.
func (c *Connection) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.info.State
}

// Protocol returns the active protocol ("wireguard" or "stealth").
func (c *Connection) Protocol() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.protocol
}

// Connect establishes a VPN connection to the given server.
// On ANY failure, all partially-created resources are torn down so the
// host network is never left in a broken state.
//
// Protocol can be "wireguard", "stealth", or "smart".
// Smart mode tries WireGuard first, then falls back to stealth on failure.
func (c *Connection) Connect(ctx context.Context, server *api.LogicalServer, kp *api.KeyPair, cert *api.CertificateResponse, certFeatures api.CertificateFeatures, enableKillSwitch bool, protocol string, customDNS []string) error {
	c.setState(StateConnecting)

	// Store connection params for reconnection
	c.mu.Lock()
	c.lastServer = server
	c.lastCertFeats = certFeatures
	c.lastKillSwitch = enableKillSwitch
	c.lastProtocol = protocol
	c.lastCustomDNS = customDNS
	c.mu.Unlock()

	var err error
	if protocol == "" || protocol == "smart" {
		err = c.connectSmart(ctx, server, kp, cert, certFeatures, enableKillSwitch, customDNS)
	} else {
		err = c.connectWithProtocol(ctx, server, kp, cert, certFeatures, enableKillSwitch, protocol, customDNS)
	}

	if err == nil {
		// Start monitoring for reconnection
		c.monitorConnection()
	}
	return err
}

// connectSmart tries WireGuard first (5s timeout), falls back to stealth.
func (c *Connection) connectSmart(ctx context.Context, server *api.LogicalServer, kp *api.KeyPair, cert *api.CertificateResponse, certFeatures api.CertificateFeatures, enableKillSwitch bool, customDNS []string) error {
	if c.onLog != nil {
		c.onLog("Smart: trying WireGuard...")
	}

	// Try WireGuard with a short 5s probe timeout
	err := c.connectWithProtocol(ctx, server, kp, cert, certFeatures, enableKillSwitch, "wireguard", customDNS, 5*time.Second)
	if err == nil {
		if c.onLog != nil {
			c.onLog("Smart: WireGuard connected")
		}
		return nil
	}

	if c.onLog != nil {
		c.onLog("Smart: WireGuard blocked, switching to Stealth...")
	}

	// WireGuard failed — need fresh keys for the new connection
	kp2, err2 := api.GenerateKeyPair()
	if err2 != nil {
		return fmt.Errorf("smart fallback keygen: %w (original: %w)", err2, err)
	}
	cert2, err2 := c.client.RequestCert(ctx, kp2, certFeatures)
	if err2 != nil {
		return fmt.Errorf("smart fallback cert: %w (original: %w)", err2, err)
	}

	c.setState(StateConnecting)
	return c.connectWithProtocol(ctx, server, kp2, cert2, certFeatures, enableKillSwitch, "stealth", customDNS, 15*time.Second)
}

func (c *Connection) connectWithProtocol(ctx context.Context, server *api.LogicalServer, kp *api.KeyPair, cert *api.CertificateResponse, certFeatures api.CertificateFeatures, enableKillSwitch bool, protocol string, customDNS []string, laTimeout ...time.Duration) error {
	c.mu.Lock()
	c.protocol = protocol
	// If a kill switch already exists (reconnection), preserve it on failure
	existingKS := c.ks != nil
	c.mu.Unlock()

	err := c.doConnect(ctx, server, kp, cert, certFeatures, enableKillSwitch, protocol, customDNS, laTimeout...)
	if err != nil {
		c.teardown(existingKS)
		c.setState(StateDisconnected)
		return err
	}
	return nil
}

// doConnect does the actual connection work. Caller handles cleanup on error.
func (c *Connection) doConnect(ctx context.Context, server *api.LogicalServer, kp *api.KeyPair, cert *api.CertificateResponse, certFeatures api.CertificateFeatures, enableKillSwitch bool, protocol string, customDNS []string, laTimeouts ...time.Duration) error {
	// Find best physical server
	ps := server.BestServer()
	if ps == nil {
		return fmt.Errorf("no online physical server for %s", server.Name)
	}

	serverIP := net.ParseIP(ps.EntryIP)
	if serverIP == nil {
		return fmt.Errorf("invalid server IP: %s", ps.EntryIP)
	}

	// Step 0: Swap the preboot kill switch table for a runtime one that
	// allows the NEW server IP, BEFORE bringing the tunnel up.
	//
	// Without this step, the preboot unit's table (loaded at early boot)
	// is still in force here — and it only allows the previous
	// connect's serverIP. Any handshake to a fresh server (different
	// IP) would be dropped by the policy-drop chain and time out. We
	// hit exactly this on Arch VM during F-3 verification: the
	// preboot table had server 79.127.141.56 baked in, but "fastest"
	// picked a stealth relay at 194.126.177.15, and the TCP dial for
	// the handshake timed out because the kill switch blocked it.
	//
	// If the user has the kill switch enabled, we replace the table
	// with one targeted at the new server (Enable is idempotent and
	// atomically swaps). If the user disabled the kill switch but a
	// preboot table is still sitting around (edge case: killswitch
	// toggled off without a reconnect, or daemon crashed mid-flow),
	// we tear it down here so the handshake can go through.
	if enableKillSwitch {
		ks, err := NewKillSwitch()
		if err != nil {
			return fmt.Errorf("create kill switch: %w", err)
		}
		// Prefer the pinned API IPs that pvpnd loaded at startup from
		// /var/lib/pvpn/api-ips.txt — at this point in the flow DNS is
		// still blocked by the preboot kill switch, so a ResolveAPIHosts
		// call would try net.LookupHost and fail. The pinned list is the
		// same one used by the HTTP client, so it is the freshest set we
		// can get without going through the tunnel.
		var apiIPs []net.IP
		for _, s := range c.client.PinnedAPIIPs() {
			if ip := net.ParseIP(s); ip != nil {
				apiIPs = append(apiIPs, ip)
			}
		}
		if len(apiIPs) == 0 {
			// No pinned IPs (fresh install, never connected) — fall back
			// to DNS. This works on the cold-install path because no
			// preboot table exists yet, so DNS is unrestricted.
			resolved, err := ResolveAPIHosts(c.client.BaseURL())
			if err != nil {
				log.Printf("kill switch: failed to pre-resolve API hosts: %v", err)
			}
			apiIPs = resolved
		}
		if err := ks.Enable(serverIP, apiIPs); err != nil {
			return fmt.Errorf("enable kill switch: %w", err)
		}
		c.mu.Lock()
		c.ks = ks
		c.mu.Unlock()
	} else {
		// Kill switch not requested but preboot table may still exist.
		// Tear it down so the handshake can dial out. Matches the
		// cleanup path in ClearPrebootKillSwitch.
		exec.Command("nft", "delete", "table", "inet", tableName).Run()
		_ = ClearPrebootKillSwitch()
	}

	// Step 0.5: Apply sysctl hardening (F-10). This closes the ARP/LAN
	// leak class where the tunnel IP can be discovered via ARP on the
	// physical NIC. Apply is idempotent — on a reconnect the existing
	// hardener is reused and the already-changed values are not
	// re-saved (so Revert still restores the ORIGINAL pre-pVPN values).
	c.mu.Lock()
	if c.sysctl == nil {
		c.sysctl = newSysctlHardener()
		c.sysctl.Apply()
	}
	c.mu.Unlock()

	// Step 1: Create tunnel (kernel WireGuard or stealth WireGuard-over-TLS)
	var tunnelLink netlink.Link
	var tunnelIfIndex int

	if protocol == "stealth" {
		// Fetch client config for the correct stealth TCP port
		stealthPort := stealth.DefaultStealthPort
		clientCfg, err := c.client.GetClientConfig(ctx)
		if err == nil && len(clientCfg.DefaultPorts.WireGuard.TCP) > 0 {
			stealthPort = clientCfg.DefaultPorts.WireGuard.TCP[0]
		}

		sm := stealth.NewStealthManager()
		sm.OnLog = c.onLog
		sCfg := &stealth.StealthConfig{
			PrivateKey: kp.WireGuardPrivateKey,
			PublicKey:  ps.X25519PublicKey,
			ServerIP:   ps.EntryIP,
			Port:       stealthPort,
			Address:    DefaultVPNAddress,
		}
		if err := sm.Up(sCfg); err != nil {
			return fmt.Errorf("bring up stealth tunnel: %w", err)
		}
		c.mu.Lock()
		c.stealthMgr = sm
		c.mu.Unlock()
		tunnelLink = sm.Link()
		tunnelIfIndex = sm.IfIndex()
	} else {
		wg, err := NewWireGuardManager()
		if err != nil {
			return fmt.Errorf("create wireguard manager: %w", err)
		}
		wgCfg := &WireGuardConfig{
			PrivateKey: kp.WireGuardPrivateKey,
			PublicKey:  ps.X25519PublicKey,
			Endpoint:   fmt.Sprintf("%s:51820", ps.EntryIP),
			Address:    DefaultVPNAddress,
		}
		if err := wg.Up(wgCfg); err != nil {
			wg.Close()
			return fmt.Errorf("bring up wireguard: %w", err)
		}
		c.mu.Lock()
		c.wg = wg
		c.mu.Unlock()
		tunnelLink = wg.Link()
		tunnelIfIndex = wg.IfIndex()
	}

	// Step 2: Set up fwmark-based policy routing
	routes := NewRouteManager(tunnelLink)
	if err := routes.Up(); err != nil {
		return fmt.Errorf("setup routes: %w", err)
	}
	c.mu.Lock()
	c.routes = routes
	c.mu.Unlock()

	// Step 3: Start Local Agent (mTLS connection to VPN server)
	features := DefaultFeatures(&certFeatures, server)
	la, err := NewLocalAgent(kp, cert, ps.Domain, features)
	if err != nil {
		return fmt.Errorf("create local agent: %w", err)
	}
	la.onLog = c.onLog
	c.mu.Lock()
	c.la = la
	c.mu.Unlock()

	laTimeout := 15 * time.Second
	if len(laTimeouts) > 0 && laTimeouts[0] > 0 {
		laTimeout = laTimeouts[0]
	}
	if err := la.WaitConnected(laTimeout); err != nil {
		return fmt.Errorf("local agent: %w", err)
	}

	// Step 4: Configure DNS
	var dnsServers []net.IP
	if len(customDNS) > 0 {
		for _, addr := range customDNS {
			if ip := net.ParseIP(addr); ip != nil {
				dnsServers = append(dnsServers, ip)
			}
		}
	}
	if len(dnsServers) == 0 {
		dnsServers = []net.IP{net.ParseIP("10.2.0.1")}
	}
	if err := c.dnsBackend.SetDNS(tunnelIfIndex, dnsServers); err != nil {
		return fmt.Errorf("setup DNS (%s): %w", c.dnsBackend.Name(), err)
	}

	// Step 5: Kill switch was already enabled at Step 0 (before tunnel
	// up) if requested. Refresh the API IP set now that the tunnel is
	// up — in-tunnel DNS can resolve vpn-api.proton.me to the current
	// set of addresses, which we then use to update the reconnect set
	// and rewrite /var/lib/pvpn/api-ips.txt for the next reboot. This
	// keeps the pinned list from going stale if Proton rotates API IPs.
	if enableKillSwitch && c.ks != nil {
		if ips, err := ResolveAPIHosts(c.client.BaseURL()); err == nil && len(ips) > 0 {
			if err := c.ks.RefreshAPIIPs(ips); err != nil {
				log.Printf("kill switch: refresh api IPs: %v", err)
			}
			if err := WritePrebootKillSwitch(serverIP, ips); err != nil {
				log.Printf("kill switch: rewrite preboot state: %v", err)
			}
			// Update the HTTP client's pinned set too so future API
			// calls use the freshest IPs.
			pinned := make([]string, 0, len(ips))
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					pinned = append(pinned, v4.String())
				}
			}
			c.client.SetPinnedAPIIPs(pinned)
		}
	}

	// Step 6: Start port forwarding if enabled (must be after full tunnel config)
	if certFeatures.PortForwarding {
		pf := NewPortForwarder(ctx, c.onLog)
		c.mu.Lock()
		c.portFwd = pf
		c.mu.Unlock()
	}

	// Success
	var fwdPort uint16
	if c.portFwd != nil {
		fwdPort = c.portFwd.Port()
	}
	var entryCountry string
	if server.IsSecureCore() {
		entryCountry = server.EntryCountry
	}
	c.mu.Lock()
	c.info = ConnectionInfo{
		ServerName:    server.Name,
		ServerIP:      ps.EntryIP,
		ServerCountry: server.ExitCountry,
		EntryCountry:  entryCountry,
		ConnectedAt:   time.Now(),
		State:         StateConnected,
		ForwardedPort: fwdPort,
	}
	c.mu.Unlock()

	if c.onState != nil {
		c.onState(StateConnected)
	}

	return nil
}

// SetKillSwitch enables or disables the kill switch on a live connection.
// Can be called while connected — takes effect immediately.
func (c *Connection) SetKillSwitch(enable bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if enable {
		if c.ks != nil {
			return nil // already enabled
		}
		// Need the server IP for the allow rule
		serverIP := net.ParseIP(c.info.ServerIP)
		if serverIP == nil {
			return fmt.Errorf("no active connection")
		}
		ks, err := NewKillSwitch()
		if err != nil {
			return err
		}
		// Pre-resolve API hosts before locking down (F-1 fix — see doConnect)
		apiIPs, err := ResolveAPIHosts(c.client.BaseURL())
		if err != nil {
			log.Printf("kill switch: failed to pre-resolve API hosts: %v", err)
		}
		if err := ks.Enable(serverIP, apiIPs); err != nil {
			return err
		}
		c.ks = ks
		c.lastKillSwitch = true
	} else {
		if c.ks == nil {
			return nil // already disabled
		}
		c.ks.Disable()
		c.ks = nil
		c.lastKillSwitch = false
	}
	return nil
}

// EnableReconnect enables automatic reconnection with exponential backoff.
// Must be called before Connect. On disconnect due to error (not user-initiated),
// the connection will automatically retry.
func (c *Connection) EnableReconnect(enabled bool) {
	c.mu.Lock()
	c.reconnect = enabled
	c.mu.Unlock()
}

// Disconnect tears down the VPN connection (user-initiated).
// Stops any reconnection attempts.
func (c *Connection) Disconnect() error {
	c.mu.Lock()
	// Cancel any ongoing reconnection
	if c.reconnectCancel != nil {
		c.reconnectCancel()
		c.reconnectCancel = nil
	}
	c.mu.Unlock()

	c.setState(StateDisconnecting)

	if err := c.teardown(); err != nil {
		c.setError(err)
		return err
	}

	c.setState(StateDisconnected)
	return nil
}

// TriggerReconnect forces an immediate reconnection check.
// Called by the daemon when the system wakes from suspend.
func (c *Connection) TriggerReconnect() {
	if c.State() != StateConnected && c.State() != StateReconnecting {
		return
	}
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

// RefreshLANSnapshot re-installs the LAN snapshot into the VPN
// routing table. Called by the daemon's network-change handler after
// a link flap: when the physical NIC goes down, the kernel purges
// every route pointing at it from *every* table (including our
// custom VPN table), and when it comes back up the kernel only
// repopulates main — leaving LAN access broken even though the
// tunnel handshake is still healthy. A cheap, idempotent re-snapshot
// fixes it without forcing a full reconnect.
func (c *Connection) RefreshLANSnapshot() {
	c.mu.RLock()
	routes := c.routes
	c.mu.RUnlock()
	if routes == nil {
		return
	}
	routes.RefreshLANSnapshot()
}

// monitorConnection watches the WireGuard handshake and triggers
// reconnection if the tunnel goes stale. A cancelable context is always
// installed so Disconnect() can stop the monitor even when automatic
// reconnection is disabled.
func (c *Connection) monitorConnection() {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.reconnectCancel = cancel
	reconnect := c.reconnect
	c.mu.Unlock()

	if !reconnect {
		// No monitoring needed, but keep the cancel installed so the
		// goroutine-free path stays consistent with the reconnect path.
		cancel()
		return
	}

	go func() {
		missedHandshakes := 0
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.wakeCh:
				// System just woke up — check immediately
				if c.State() != StateConnected {
					return
				}
				log.Printf("System resumed from sleep, checking connection...")
				if c.onLog != nil {
					c.onLog("System resumed from sleep, checking connection...")
				}
				// Wait for the network to come back (WiFi reconnect, DHCP, etc.)
				// then check whether the tunnel survived suspend.
				if !c.waitForNetwork(ctx, 15*time.Second) {
					log.Printf("Network not available after wake, triggering reconnect")
					c.setState(StateReconnecting)
					if c.onLog != nil {
						c.onLog("Network not available after wake, reconnecting...")
					}
					c.doReconnect(ctx)
					return
				}
				stats, err := c.Stats()
				if err != nil || time.Since(stats.LastHandshake) > 30*time.Second {
					log.Printf("Connection stale after wake (err=%v), triggering reconnect", err)
					c.setState(StateReconnecting)
					if c.onLog != nil {
						c.onLog("Connection stale after wake, reconnecting...")
					}
					c.doReconnect(ctx)
					return
				}
				log.Printf("Connection still healthy after wake")
				if c.onLog != nil {
					c.onLog("Connection still healthy after wake")
				}
				missedHandshakes = 0
			case <-ticker.C:
				if c.State() != StateConnected {
					return
				}
				stats, err := c.Stats()
				if err != nil {
					missedHandshakes++
				} else if time.Since(stats.LastHandshake) > 3*time.Minute {
					missedHandshakes++
				} else {
					missedHandshakes = 0
				}

				// If we've missed handshakes for 30s, trigger reconnect
				if missedHandshakes >= 3 {
					c.setState(StateReconnecting)
					if c.onLog != nil {
						c.onLog("Connection stale, reconnecting...")
					}
					c.doReconnect(ctx)
					return
				}
			}
		}
	}()
}

// doReconnect attempts to reconnect with exponential backoff.
// It retries indefinitely until the connection succeeds or the context
// is cancelled (user disconnect). A wake signal on wakeCh resets the
// backoff so reconnection is attempted immediately after resume.
func (c *Connection) doReconnect(ctx context.Context) {
	c.mu.RLock()
	server := c.lastServer
	certFeats := c.lastCertFeats
	ks := c.lastKillSwitch
	protocol := c.lastProtocol
	customDNS := c.lastCustomDNS
	c.mu.RUnlock()

	if server == nil {
		return
	}

	// Check if kill switch is active — if so, keep it during reconnection
	// to prevent traffic leaks.
	c.mu.RLock()
	hasKillSwitch := c.ks != nil
	c.mu.RUnlock()

	// Tear down the broken connection but preserve the kill switch
	log.Printf("Reconnect: tearing down stale connection (keepKillSwitch=%v)", hasKillSwitch)
	c.teardown(hasKillSwitch)
	log.Printf("Reconnect: teardown complete")

	backoff := 2 * time.Second
	maxBackoff := 2 * time.Minute

retryLoop:
	for attempt := 1; ; attempt++ {
		select {
		case <-ctx.Done():
			// User-initiated disconnect — now fully tear down kill switch
			if hasKillSwitch {
				c.teardown()
			}
			c.setState(StateDisconnected)
			return
		default:
		}

		// Wait for the underlying network before burning an attempt
		log.Printf("Reconnect: waiting for network...")
		if !c.waitForNetwork(ctx, 30*time.Second) {
			log.Printf("Reconnect: network still not available, retrying wait...")
			continue
		}
		log.Printf("Reconnect: network is back")

		// Note: no API pinhole dance here anymore. The kill switch's
		// reconnect set was pre-seeded with resolved Proton API IPs at
		// Enable time, so the API is reachable via @pvpn_reconnect without
		// any DNS egress (pre-v0.2.1 F-1 fix).

		log.Printf("Reconnect attempt %d...", attempt)
		if c.onLog != nil {
			c.onLog(fmt.Sprintf("Reconnect attempt %d...", attempt))
		}

		err := c.reconnectAttempt(ctx, server, certFeats, ks, protocol, customDNS, hasKillSwitch)
		if err == nil {
			log.Printf("Reconnected successfully")
			if c.onLog != nil {
				c.onLog("Reconnected successfully")
			}
			c.monitorConnection()
			return
		}
		log.Printf("Reconnect attempt %d failed: %v", attempt, err)

		// Wait for backoff, but allow wake signal to skip the wait
		select {
		case <-ctx.Done():
			if hasKillSwitch {
				c.teardown()
			}
			c.setState(StateDisconnected)
			return
		case <-c.wakeCh:
			// System woke up — retry immediately with reset backoff
			backoff = 2 * time.Second
			continue retryLoop
		case <-time.After(backoff):
		}

		backoff = nextBackoff(backoff, maxBackoff)
	}
}

// reconnectAttempt performs a single reconnect attempt: generate keys,
// request a cert, and call doConnect. Returns nil on success. On error
// it tears down any partial state (preserving the kill switch). It is
// split out from doReconnect so the outer backoff loop reads linearly
// without goto.
func (c *Connection) reconnectAttempt(ctx context.Context, server *api.LogicalServer, certFeats api.CertificateFeatures, ks bool, protocol string, customDNS []string, hasKillSwitch bool) error {
	kp, err := api.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	cert, err := c.client.RequestCert(ctx, kp, certFeats)
	if err != nil {
		return fmt.Errorf("request cert: %w", err)
	}

	// Call doConnect directly — NOT connectWithProtocol — so we
	// control state ourselves. connectWithProtocol would broadcast
	// StateDisconnected on every failed attempt, confusing the TUI.
	c.mu.Lock()
	c.protocol = protocol
	c.mu.Unlock()

	if err := c.doConnect(ctx, server, kp, cert, certFeats, ks, protocol, customDNS, 15*time.Second); err != nil {
		// Clean up partial state from failed attempt, keep kill switch
		c.teardown(hasKillSwitch)
		return err
	}

	// Refresh the pinned API IPs now that the tunnel is up and in-tunnel
	// DNS can return the current set. Best-effort — if it fails, we still
	// have the pre-seeded IPs from the original Enable call.
	if hasKillSwitch {
		c.mu.RLock()
		activeKS := c.ks
		c.mu.RUnlock()
		if activeKS != nil {
			if ips, err := ResolveAPIHosts(c.client.BaseURL()); err == nil {
				_ = activeKS.RefreshAPIIPs(ips)
			}
		}
	}
	return nil
}

// nextBackoff doubles the current backoff duration, capped at cap.
// Extracted for unit testing.
func nextBackoff(current, ceiling time.Duration) time.Duration {
	next := current * 2
	if next > ceiling {
		return ceiling
	}
	return next
}

// waitForNetwork polls until a default gateway is present in the main routing
// table, meaning the underlying network (WiFi/ethernet) is back after suspend.
// Returns true if network came back within the timeout, false otherwise.
func (c *Connection) waitForNetwork(ctx context.Context, timeout time.Duration) bool {
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-ticker.C:
			if hasDefaultRoute() {
				return true
			}
		}
	}
}

// hasDefaultRoute checks the main routing table (254) for a default route
// with a gateway. This is a lightweight netlink check — no traffic is sent.
func hasDefaultRoute() bool {
	// Filter to main table only — we don't want to match the VPN table's
	// default route which has no gateway.
	filter := &netlink.Route{Table: 254} // main table
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false
	}
	for _, r := range routes {
		// Default route: Dst is nil or 0.0.0.0/0, and has a gateway
		isDefault := r.Dst == nil || (r.Dst.IP.Equal(net.IPv4zero) && r.Dst.Mask != nil &&
			net.IP(r.Dst.Mask).Equal(net.IPv4zero))
		if isDefault && r.Gw != nil {
			return true
		}
	}
	return false
}

// Stats returns the current WireGuard peer statistics.
func (c *Connection) Stats() (*PeerStats, error) {
	c.mu.RLock()
	wg := c.wg
	sm := c.stealthMgr
	c.mu.RUnlock()

	if sm != nil {
		rx, tx, hs, err := sm.Stats()
		if err != nil {
			return nil, err
		}
		return &PeerStats{RxBytes: rx, TxBytes: tx, LastHandshake: hs}, nil
	}
	if wg != nil {
		return wg.Stats()
	}
	return nil, fmt.Errorf("not connected")
}

// teardown reverses all connection steps in reverse order.
// If keepKillSwitch is true, the kill switch rules are left active so traffic
// cannot leak during reconnection.
func (c *Connection) teardown(keepKillSwitch ...bool) error {
	preserveKS := len(keepKillSwitch) > 0 && keepKillSwitch[0]

	c.mu.Lock()
	pf := c.portFwd
	c.portFwd = nil
	la := c.la
	ks := c.ks
	routes := c.routes
	wg := c.wg
	sm := c.stealthMgr
	dnsBackend := c.dnsBackend
	ifIndex := c.tunnelIfIndex()
	// Only revert sysctl hardening on FULL teardown (user disconnect
	// or fatal error). Reconnect keeps the kill switch AND keeps the
	// sysctl hardening so there is never a window where the tunnel IP
	// can be ARP-probed on the physical NIC.
	var sysctl *sysctlHardener
	if !preserveKS {
		sysctl = c.sysctl
		c.sysctl = nil
	}
	c.mu.Unlock()

	var firstErr error

	// Stop port forwarding first (it uses the tunnel)
	if pf != nil {
		pf.Stop()
	}

	// Reverse order: local agent -> kill switch -> DNS -> routes -> tunnel

	if la != nil {
		la.Close()
		c.mu.Lock()
		c.la = nil
		c.mu.Unlock()
	}

	if ks != nil && !preserveKS {
		if err := ks.Disable(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("disable kill switch: %w", err)
		}
		c.mu.Lock()
		c.ks = nil
		c.mu.Unlock()
	}

	if ifIndex > 0 && dnsBackend != nil {
		if err := dnsBackend.RevertDNS(ifIndex); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("revert DNS: %w", err)
		}
	}

	if routes != nil {
		if err := routes.Down(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("teardown routes: %w", err)
		}
		c.mu.Lock()
		c.routes = nil
		c.mu.Unlock()
	}

	if sm != nil {
		if err := sm.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("teardown stealth: %w", err)
		}
		c.mu.Lock()
		c.stealthMgr = nil
		c.mu.Unlock()
	}

	if wg != nil {
		if err := wg.Down(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("teardown wireguard: %w", err)
		}
		wg.Close()
		c.mu.Lock()
		c.wg = nil
		c.mu.Unlock()
	}

	// Revert sysctl hardening last — after the tunnel interface is
	// gone — so there is no window where the kernel accepts ARP for
	// the old tunnel IP while the interface still technically exists.
	if sysctl != nil {
		sysctl.Revert()
	}

	return firstErr
}

// ForwardedPort returns the currently assigned external port (0 if none).
func (c *Connection) ForwardedPort() uint16 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.portFwd != nil {
		return c.portFwd.Port()
	}
	return 0
}

func (c *Connection) setState(state State) {
	c.mu.Lock()
	c.info.State = state
	c.info.LastError = nil
	c.mu.Unlock()

	if c.onState != nil {
		c.onState(state)
	}
}

func (c *Connection) setError(err error) {
	c.mu.Lock()
	c.info.State = StateError
	c.info.LastError = err
	c.mu.Unlock()

	if c.onState != nil {
		c.onState(StateError)
	}
}
