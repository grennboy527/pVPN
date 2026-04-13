package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/YourDoritos/pvpn/internal/ipc"
	"github.com/YourDoritos/pvpn/internal/network"
	"github.com/YourDoritos/pvpn/internal/vpn"
)

// Daemon is the privileged VPN service.
type Daemon struct {
	mu sync.RWMutex

	cfg    *config.Config
	client *api.Client
	store  *api.SessionStore
	conn   *vpn.Connection

	vpnInfo    *api.VPNInfoResponse
	serverList []api.LogicalServer

	// Connected IPC clients for push events
	clients   map[*ipc.Conn]struct{}
	clientsMu sync.RWMutex

	sessionReady chan struct{} // closed when initSession completes

	listener net.Listener
	sleepMon *sleepMonitor
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates a new daemon instance.
func New(cfg *config.Config, client *api.Client, store *api.SessionStore) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:          cfg,
		client:       client,
		store:        store,
		clients:      make(map[*ipc.Conn]struct{}),
		sessionReady: make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Run starts the daemon: IPC listener + optional auto-connect.
func (d *Daemon) Run(socketPath string) error {
	// Ensure socket directory exists
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	// Remove stale socket
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socketPath, err)
	}
	d.listener = ln

	// Restrict socket to root + members of the pvpn group. If the group
	// doesn't exist (fresh install without the group, dev/test loops),
	// fall back to root-only (0600) — daemon still works, but only root
	// can talk to it until the group is created.
	if grp, err := user.LookupGroup(config.SocketGroup); err == nil {
		gid, convErr := strconv.Atoi(grp.Gid)
		if convErr != nil {
			log.Printf("warning: parse pvpn gid %q: %v — falling back to root-only socket", grp.Gid, convErr)
			os.Chmod(socketPath, 0600)
		} else if err := os.Chown(socketPath, 0, gid); err != nil {
			log.Printf("warning: chown socket to root:%s: %v — falling back to root-only", config.SocketGroup, err)
			os.Chmod(socketPath, 0600)
		} else {
			os.Chmod(socketPath, 0660)
		}
	} else {
		log.Printf("warning: group %q not found — IPC socket restricted to root. Create the group and add your user to enable unprivileged clients.", config.SocketGroup)
		os.Chmod(socketPath, 0600)
	}

	log.Printf("Daemon listening on %s", socketPath)

	// Clean up any stale VPN state from a previous daemon instance
	vpn.ForceCleanup()

	// Monitor system suspend/resume to trigger VPN reconnection on wake
	d.sleepMon = newSleepMonitor(d.onSystemWake)

	// Try to restore session and load servers in background
	go d.initSession()

	// Auto-connect if configured
	go d.autoConnect()

	// Accept IPC clients
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go d.handleClient(ipc.NewConn(conn))
	}
}

// Stop shuts down the daemon.
func (d *Daemon) Stop() {
	d.cancel()
	d.sleepMon.Stop()
	if d.listener != nil {
		d.listener.Close()
	}
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()
	if conn != nil {
		conn.Disconnect()
	}
	vpn.ForceCleanup()
}

func (d *Daemon) signalSessionReady() {
	select {
	case <-d.sessionReady:
		// already closed
	default:
		close(d.sessionReady)
	}
}

func (d *Daemon) initSession() {
	defer d.signalSessionReady()

	if !d.client.IsAuthenticated() {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()

	info, err := d.client.GetVPNInfo(ctx)
	if err != nil {
		// Only clear the session for permanent auth errors (revoked token,
		// disabled account, etc.). Transient errors (network timeout, DNS
		// not ready at boot, API hiccup) should NOT destroy the session —
		// the tokens may still be perfectly valid.
		if api.IsAuthError(err) {
			log.Printf("Session invalid (auth error): %v", err)
			d.client.SetSession("", "", "")
		} else {
			log.Printf("Session validation failed (transient, keeping session): %v", err)
		}
		return
	}
	d.mu.Lock()
	d.vpnInfo = info
	d.mu.Unlock()
	log.Printf("Session restored: %s (tier %d)", info.VPN.PlanTitle, info.VPN.MaxTier)

	// Load server list
	servers, err := d.client.GetServers(ctx)
	if err != nil {
		log.Printf("Failed to load servers: %v", err)
		return
	}
	d.mu.Lock()
	d.serverList = servers.LogicalServers
	d.mu.Unlock()
	log.Printf("Loaded %d servers", len(servers.LogicalServers))
}

func (d *Daemon) autoConnect() {
	if !d.cfg.Connection.AutoConnect {
		return
	}
	// Wait for session init to finish (no fixed timeout — just wait for the signal)
	select {
	case <-d.sessionReady:
	case <-d.ctx.Done():
		return
	}

	d.mu.RLock()
	authenticated := d.client.IsAuthenticated()
	servers := d.serverList
	d.mu.RUnlock()

	if !authenticated || len(servers) == 0 {
		return
	}

	// Smart auto-connect: use last country + saved filters to find best server
	filter := api.ServerFilter{
		OnlineOnly: true,
		Country:    d.cfg.Server.LastCountry,
		Tor:        d.cfg.Server.FilterTor,
		Streaming:  d.cfg.Server.FilterStreaming,
		SecureCore: d.cfg.Server.FilterSecureCore,
		P2P:        d.cfg.Server.FilterP2P,
	}
	server := api.FindFastestServer(servers, filter, d.userTier())

	// Fallback: try without filters, then without country
	if server == nil {
		filter.Tor = false
		filter.Streaming = false
		filter.SecureCore = false
		filter.P2P = false
		server = api.FindFastestServer(servers, filter, d.userTier())
	}
	if server == nil {
		filter.Country = ""
		server = api.FindFastestServer(servers, filter, d.userTier())
	}
	if server == nil {
		log.Printf("Auto-connect: no suitable server found")
		return
	}

	log.Printf("Auto-connecting to %s (%s)...", server.Name, server.ExitCountry)
	if err := d.doConnect(server, d.cfg.Connection.Protocol); err != nil {
		log.Printf("Auto-connect failed: %v", err)
	}
}

func (d *Daemon) handleClient(c *ipc.Conn) {
	// Register for push events
	d.clientsMu.Lock()
	d.clients[c] = struct{}{}
	d.clientsMu.Unlock()

	defer func() {
		d.clientsMu.Lock()
		delete(d.clients, c)
		d.clientsMu.Unlock()
		c.Close()
	}()

	for {
		var req ipc.Request
		if err := ipc.ReadJSON(c.Reader, &req); err != nil {
			return // client disconnected
		}

		resp := d.handleCommand(&req, c)
		if err := c.SendResponse(resp); err != nil {
			return
		}
	}
}

func (d *Daemon) handleCommand(req *ipc.Request, c *ipc.Conn) *ipc.Response {
	switch req.Command {
	case "status":
		return d.cmdStatus()
	case "connect":
		return d.cmdConnect(req.Params)
	case "disconnect":
		return d.cmdDisconnect()
	case "login":
		return d.cmdLogin(req.Params)
	case "servers":
		return d.cmdServers()
	case "settings":
		return d.cmdSettings(req.Params)
	case "logout":
		return d.cmdLogout()
	default:
		return &ipc.Response{OK: false, Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}

func (d *Daemon) cmdStatus() *ipc.Response {
	d.mu.RLock()
	conn := d.conn
	authenticated := d.client.IsAuthenticated()
	d.mu.RUnlock()

	data := ipc.StatusData{State: "disconnected"}

	if !authenticated {
		data.State = "not_authenticated"
		return &ipc.Response{OK: true, Data: ipc.MarshalData(data)}
	}

	data.Username = d.client.LoginEmail()
	d.mu.RLock()
	if d.vpnInfo != nil {
		data.PlanName = d.vpnInfo.VPN.PlanTitle
	}
	d.mu.RUnlock()

	if conn != nil {
		info := conn.Info()
		data.State = info.State.String()
		data.Server = info.ServerName
		data.ServerIP = info.ServerIP
		data.Country = info.ServerCountry
		data.EntryCountry = info.EntryCountry
		if info.State == vpn.StateConnected {
			data.Duration = int64(time.Since(info.ConnectedAt).Seconds())
			if stats, err := conn.Stats(); err == nil {
				data.RxBytes = stats.RxBytes
				data.TxBytes = stats.TxBytes
				data.Handshake = stats.LastHandshake.Unix()
			}
			data.ForwardedPort = conn.ForwardedPort()
		}
		d.mu.RLock()
		data.Protocol = d.conn.Protocol()
		d.mu.RUnlock()
	}

	return &ipc.Response{OK: true, Data: ipc.MarshalData(data)}
}

func (d *Daemon) cmdConnect(params json.RawMessage) *ipc.Response {
	var p ipc.ConnectParams
	if err := json.Unmarshal(params, &p); err != nil {
		return &ipc.Response{OK: false, Error: fmt.Sprintf("invalid params: %v", err)}
	}

	d.mu.RLock()
	servers := d.serverList
	d.mu.RUnlock()

	if len(servers) == 0 {
		return &ipc.Response{OK: false, Error: "no servers loaded (not authenticated?)"}
	}

	// Find the requested server
	var server *api.LogicalServer
	if p.Server == "fastest" || p.Server == "" {
		server = api.FindFastestServer(servers, api.ServerFilter{OnlineOnly: true}, d.userTier())
	} else {
		server = api.FindServerByName(servers, p.Server)
		if server == nil {
			// Try as country code
			server = api.FindFastestServer(servers, api.ServerFilter{
				Country: p.Server, OnlineOnly: true,
			}, d.userTier())
		}
	}

	if server == nil {
		return &ipc.Response{OK: false, Error: fmt.Sprintf("server not found: %s", p.Server)}
	}

	protocol := p.Protocol
	if protocol == "" {
		protocol = d.cfg.Connection.Protocol
	}

	// Connect in background, return immediately. The doConnect context
	// is derived from d.ctx so daemon shutdown cancels it, and capped
	// at connectTimeout so a stuck attempt doesn't hang forever.
	go func() {
		if err := d.doConnect(server, protocol); err != nil {
			d.broadcast(&ipc.Event{
				Type: "state-changed",
				Data: ipc.MarshalData(ipc.StateChangedData{
					State: "error",
					Error: err.Error(),
				}),
			})
		}
	}()

	return &ipc.Response{OK: true}
}

func (d *Daemon) doConnect(server *api.LogicalServer, protocol string) error {
	d.mu.Lock()
	// Disconnect existing if any
	if d.conn != nil {
		d.conn.Disconnect()
		d.conn = nil
	}
	d.mu.Unlock()

	// Reload config so we pick up any settings the TUI changed
	// (kill switch, netshield, etc.) since the daemon started.
	d.cfg.Reload()

	// Cap the initial connect attempt so a stuck handshake or hung
	// TLS dial can't wedge the daemon forever. Derived from d.ctx so
	// daemon shutdown still cancels mid-connect.
	ctx, cancel := context.WithTimeout(d.ctx, 2*time.Minute)
	defer cancel()

	dnsBackend, err := network.DetectBackend()
	if err != nil {
		return fmt.Errorf("detect network backend: %w", err)
	}

	kp, err := api.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}

	certFeatures := api.CertificateFeatures{
		NetShieldLevel: d.cfg.Features.NetShield,
		SplitTCP:       d.cfg.Features.VPNAccelerator,
		RandomNAT:      !d.cfg.Features.ModerateNAT,
		PortForwarding: d.cfg.Features.PortForwarding,
	}

	cert, err := d.client.RequestCert(ctx, kp, certFeatures)
	if err != nil {
		return fmt.Errorf("request certificate: %w", err)
	}

	conn := vpn.NewConnection(d.client, dnsBackend)
	conn.EnableReconnect(d.cfg.Connection.Reconnect)

	// Wire up event broadcasting
	conn.OnStateChange(func(state vpn.State) {
		d.broadcast(&ipc.Event{
			Type: "state-changed",
			Data: ipc.MarshalData(ipc.StateChangedData{
				State:        state.String(),
				Server:       server.Name,
				Country:      server.ExitCountry,
				EntryCountry: server.EntryCountry,
			}),
		})
	})
	conn.OnLog(func(msg string) {
		d.broadcast(&ipc.Event{
			Type: "log",
			Data: ipc.MarshalData(ipc.LogData{Message: msg}),
		})
	})

	d.broadcast(&ipc.Event{
		Type: "state-changed",
		Data: ipc.MarshalData(ipc.StateChangedData{
			State:        "Connecting",
			Server:       server.Name,
			Country:      server.ExitCountry,
			EntryCountry: server.EntryCountry,
		}),
	})

	if err := conn.Connect(ctx, server, kp, cert, certFeatures, d.cfg.Connection.KillSwitch, protocol, d.cfg.DNS.CustomDNS); err != nil {
		return err
	}

	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()

	// Reload config from disk before saving so we don't clobber settings
	// changed by the TUI (e.g., kill switch, protocol) with stale values.
	d.cfg.Reload()
	d.cfg.Server.LastServer = server.Name
	d.cfg.Server.LastCountry = server.ExitCountry
	d.cfg.AddHistory(server.Name)
	d.cfg.Save()

	// Start stats broadcast ticker
	go d.broadcastStats()

	return nil
}

func (d *Daemon) cmdDisconnect() *ipc.Response {
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.mu.Unlock()

	if conn == nil {
		return &ipc.Response{OK: true}
	}

	if err := conn.Disconnect(); err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}
	return &ipc.Response{OK: true}
}

func (d *Daemon) cmdLogin(params json.RawMessage) *ipc.Response {
	var p ipc.LoginParams
	if err := json.Unmarshal(params, &p); err != nil {
		return &ipc.Response{OK: false, Error: fmt.Sprintf("invalid params: %v", err)}
	}

	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()

	authResp, err := d.client.Login(ctx, p.Username, p.Password)
	if err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}

	if api.Needs2FA(authResp) {
		if p.TwoFA == "" {
			return &ipc.Response{OK: false, Error: "2fa_required"}
		}
		if err := d.client.Submit2FA(ctx, p.TwoFA); err != nil {
			return &ipc.Response{OK: false, Error: err.Error()}
		}
	}

	// Save session
	session := d.client.GetSession()
	d.store.Save(&session)

	// Load VPN info and servers
	d.initSession()

	return &ipc.Response{OK: true}
}

func (d *Daemon) cmdServers() *ipc.Response {
	d.mu.RLock()
	servers := d.serverList
	d.mu.RUnlock()

	filtered := api.FilterServers(servers, api.ServerFilter{OnlineOnly: true}, d.userTier())

	entries := make([]ipc.ServerEntry, 0, len(filtered))
	for _, s := range filtered {
		entries = append(entries, ipc.ServerEntry{
			Name:     s.Name,
			Country:  s.ExitCountry,
			City:     s.City,
			Load:     s.Load,
			Tier:     s.Tier,
			Features: s.Features,
			Online:   true,
		})
	}

	return &ipc.Response{OK: true, Data: ipc.MarshalData(ipc.ServersData{Servers: entries})}
}

func (d *Daemon) cmdLogout() *ipc.Response {
	// Disconnect first if connected
	d.mu.Lock()
	if d.conn != nil {
		d.conn.Disconnect()
		d.conn = nil
	}
	d.client.SetSession("", "", "")
	d.vpnInfo = nil
	d.serverList = nil
	d.mu.Unlock()

	// Delete session file
	d.store.Delete()

	d.broadcast(&ipc.Event{
		Type: "state-changed",
		Data: ipc.MarshalData(ipc.StateChangedData{State: "Disconnected"}),
	})

	return &ipc.Response{OK: true}
}

func (d *Daemon) cmdSettings(params json.RawMessage) *ipc.Response {
	// Reload config from disk to pick up TUI changes, then apply any
	// settings that can take effect on a live connection.
	oldKS := d.cfg.Connection.KillSwitch
	d.cfg.Reload()
	newKS := d.cfg.Connection.KillSwitch

	// Apply kill switch change to the live connection immediately
	if oldKS != newKS {
		d.mu.RLock()
		conn := d.conn
		d.mu.RUnlock()
		if conn != nil && conn.State() == vpn.StateConnected {
			if err := conn.SetKillSwitch(newKS); err != nil {
				log.Printf("Live kill switch toggle failed: %v", err)
			} else {
				log.Printf("Kill switch %s on live connection", map[bool]string{true: "enabled", false: "disabled"}[newKS])
			}
		}
	}

	return &ipc.Response{OK: true, Data: ipc.MarshalData(d.cfg)}
}

func (d *Daemon) userTier() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.vpnInfo != nil {
		return d.vpnInfo.VPN.MaxTier
	}
	return 0
}

// onSystemWake is called by the sleep monitor when the system resumes from suspend.
func (d *Daemon) onSystemWake() {
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()

	if conn == nil {
		return
	}

	// Signal the connection's monitor/reconnect loop to act immediately
	conn.TriggerReconnect()
}

func (d *Daemon) broadcast(evt *ipc.Event) {
	d.clientsMu.RLock()
	defer d.clientsMu.RUnlock()
	for c := range d.clients {
		c.SendEvent(evt) // ignore errors, client may have disconnected
	}
}

func (d *Daemon) broadcastStats() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.mu.RLock()
			conn := d.conn
			d.mu.RUnlock()

			if conn == nil {
				return
			}

			// During reconnection, keep the goroutine alive but skip stats.
			// This prevents the goroutine from exiting permanently when the
			// connection temporarily enters Reconnecting/Connecting state.
			if conn.State() != vpn.StateConnected {
				continue
			}

			stats, err := conn.Stats()
			if err != nil {
				continue
			}

			d.broadcast(&ipc.Event{
				Type: "stats-update",
				Data: ipc.MarshalData(ipc.StatsUpdateData{
					RxBytes:   stats.RxBytes,
					TxBytes:   stats.TxBytes,
					Handshake: stats.LastHandshake.Unix(),
				}),
			})
		}
	}
}
