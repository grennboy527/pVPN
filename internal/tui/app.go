package tui

import (
	"context"
	"encoding/json"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/YourDoritos/pvpn/internal/ipc"
	"github.com/YourDoritos/pvpn/internal/network"
	"github.com/YourDoritos/pvpn/internal/vpn"
)

type View int

const (
	ViewLoading View = iota
	ViewLogin
	ViewServers
	ViewStatus
	ViewSettings
)

// Package-level program reference for sending messages from background goroutines.
var globalProgram *tea.Program

// SetProgram stores the tea.Program reference for async VPN state updates.
func SetProgram(p *tea.Program) {
	globalProgram = p
}

type App struct {
	width  int
	height int

	view     View
	login    LoginModel
	servers  ServersModel
	status   StatusModel
	settings SettingsModel

	// Daemon mode (Phase 3)
	daemonClient *ipc.Client
	daemonMode   bool

	// Standalone mode (Phase 1-2 compat)
	client     *api.Client
	store      *api.SessionStore
	cfg        *config.Config
	conn       *vpn.Connection
	vpnInfo    *api.VPNInfoResponse
	serverList []api.LogicalServer

	authenticated bool
}

type sessionRestoredMsg struct {
	VPNInfo    *api.VPNInfoResponse
	Servers    []api.LogicalServer
	Connected  bool
	StatusData *ipc.StatusData
}
type sessionExpiredMsg struct{}
type serversLoadedMsg struct {
	Servers []api.LogicalServer
	Err     error
}
type connectErrorMsg struct{ Err error }
type daemonEventMsg struct{ Event *ipc.Event }

func NewApp(client *api.Client, store *api.SessionStore, cfg *config.Config) App {
	return App{
		view:   ViewLoading,
		client: client,
		store:  store,
		cfg:    cfg,
		login:  NewLoginModel(),
	}
}

const navHeight = 3 // tab border-top + tab content + tab border-bottom

func (a App) contentHeight() int {
	return a.height - navHeight
}

// IsDaemonMode returns true if the TUI is connected to the daemon via IPC.
func (a App) IsDaemonMode() bool {
	return a.daemonMode
}

func (a App) Init() tea.Cmd {
	return a.tryConnect()
}

// tryConnect tries daemon first, falls back to standalone.
func (a App) tryConnect() tea.Cmd {
	return func() tea.Msg {
		// Try daemon
		dc, err := ipc.Dial()
		if err == nil {
			// Daemon is running — get status
			status, err := dc.Status()
			if err != nil {
				dc.Close()
				return sessionExpiredMsg{}
			}
			if status.State == "not_authenticated" {
				return daemonConnectedMsg{client: dc, needLogin: true}
			}

			// Authenticated — fetch servers
			serversData, _ := dc.Servers()
			var servers []api.LogicalServer
			if serversData != nil {
				for _, s := range serversData.Servers {
					servers = append(servers, api.LogicalServer{
						Name:        s.Name,
						ExitCountry: s.Country,
						City:        s.City,
						Load:        s.Load,
						Tier:        s.Tier,
						Features:    s.Features,
						Status:      boolToStatus(s.Online),
					})
				}
			}

			return daemonConnectedMsg{
				client:  dc,
				status:  status,
				servers: servers,
			}
		}

		// No daemon — standalone mode
		if !a.client.IsAuthenticated() {
			return sessionExpiredMsg{}
		}
		ctx := context.Background()
		info, err := a.client.GetVPNInfo(ctx)
		if err != nil {
			// Only clear session on permanent auth errors, not transient failures
			if api.IsAuthError(err) {
				a.client.SetSession("", "", "")
				return sessionExpiredMsg{}
			}
			// Transient error — keep session, still show login so user can retry
			return sessionExpiredMsg{}
		}
		return sessionRestoredMsg{VPNInfo: info}
	}
}

type daemonConnectedMsg struct {
	client    *ipc.Client
	status    *ipc.StatusData
	servers   []api.LogicalServer
	needLogin bool
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.login.SetSize(msg.Width, msg.Height) // login uses full height (no nav)
		a.servers.SetSize(msg.Width, a.contentHeight())
		a.status.SetSize(msg.Width, a.contentHeight())
		a.settings.SetSize(msg.Width, a.contentHeight())
		return a, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			// In daemon mode, just quit TUI — VPN keeps running
			if a.daemonMode {
				if a.daemonClient != nil {
					a.daemonClient.Close()
				}
				return a, tea.Quit
			}
			// Standalone: disconnect
			if a.conn != nil {
				a.conn.Disconnect()
			}
			return a, tea.Quit
		}

		// Global tab navigation
		if a.authenticated && (a.view != ViewLogin || !a.login.InputFocused()) {
			switch msg.String() {
			case "1":
				a.view = ViewStatus
				if a.daemonMode {
					if a.status.state == "reconnecting" || a.status.state == "connecting" {
						return a, SpinnerTickCmd()
					}
					return a, a.pollDaemonStatus()
				}
				if a.conn != nil && a.conn.State() == vpn.StateConnected {
					return a, TickCmd()
				}
				if a.status.state == "reconnecting" || a.status.state == "connecting" {
					return a, SpinnerTickCmd()
				}
				return a, nil
			case "2":
				a.view = ViewServers
				return a, nil
			case "3":
				a.view = ViewSettings
				a.settings = NewSettingsModel()
				a.settings.SetSize(a.width, a.contentHeight())
				if a.daemonMode && a.daemonClient != nil {
					return a, a.fetchAccountInfo()
				}
				return a, nil
			}
		}

	case daemonConnectedMsg:
		a.daemonMode = true
		a.daemonClient = msg.client
		if msg.needLogin {
			a.view = ViewLogin
			a.login = NewLoginModel()
			a.login.SetSize(a.width, a.height)
			return a, a.login.Init()
		}
		a.authenticated = true
		a.serverList = msg.servers
		a.vpnInfo = &api.VPNInfoResponse{VPN: api.VPNInfo{MaxTier: 2}} // daemon handles tier
		a.servers = NewServersModel(a.vpnInfo)
		a.servers.LoadFilters(a.cfg)
		a.servers.SetSize(a.width, a.contentHeight())
		if len(msg.servers) > 0 {
			a.servers.SetServers(msg.servers)
		}

		// Start listening for daemon events
		a.startDaemonEvents()

		// If already connected, show status
		if msg.status != nil && msg.status.State == "Connected" {
			a.view = ViewStatus
			a.status = NewStatusModel()
			a.status.SetSize(a.width, a.contentHeight())
			a.status.SetConnectedFromDaemon(msg.status)
			a.servers.SetVPNState("connected")
			a.servers.SetConnectedServer(msg.status.Server)
			return a, TickCmd()
		}

		a.view = ViewServers
		if len(msg.servers) == 0 {
			return a, a.loadServersDaemon()
		}
		return a, nil

	case sessionRestoredMsg:
		a.authenticated = true
		a.vpnInfo = msg.VPNInfo
		a.view = ViewServers
		a.servers = NewServersModel(a.vpnInfo)
		a.servers.LoadFilters(a.cfg)
		a.servers.SetSize(a.width, a.contentHeight())
		return a, a.loadServers()

	case sessionExpiredMsg:
		a.view = ViewLogin
		a.login = NewLoginModel()
		a.login.SetSize(a.width, a.height)
		return a, a.login.Init()

	case LoginSuccessMsg:
		a.authenticated = true
		a.vpnInfo = msg.VPNInfo
		a.view = ViewServers
		a.servers = NewServersModel(a.vpnInfo)
		a.servers.LoadFilters(a.cfg)
		a.servers.SetSize(a.width, a.contentHeight())
		if a.daemonMode {
			return a, a.loadServersDaemon()
		}
		return a, a.loadServers()

	case serversLoadedMsg:
		if msg.Err != nil {
			a.servers.SetError(msg.Err)
		} else {
			a.serverList = msg.Servers
			a.servers.SetServers(msg.Servers)
		}
		return a, nil

	case ConnectRequestMsg:
		a.view = ViewStatus
		a.status = NewStatusModel()
		a.status.SetSize(a.width, a.contentHeight())
		a.status.SetConnecting(msg.Server.Name, msg.Server.ExitCountry)
		a.servers.SetVPNState("connecting")
		a.servers.SetConnectedServer(msg.Server.Name)
		if a.daemonMode {
			return a, tea.Batch(a.connectDaemon(msg.Server), SpinnerTickCmd())
		}
		return a, tea.Batch(connectToServer(a.client, a.cfg, msg.Server), SpinnerTickCmd())

	case ConnectedMsg:
		a.conn = msg.Conn
		a.status.SetConnected(msg.Info)
		a.servers.SetVPNState("connected")
		if globalProgram != nil {
			msg.Conn.OnStateChange(func(state vpn.State) {
				globalProgram.Send(VPNStateChangedMsg{State: state})
			})
		}
		return a, TickCmd()

	case VPNStateChangedMsg:
		switch msg.State {
		case vpn.StateReconnecting:
			a.view = ViewStatus
			a.status.SetReconnecting()
			a.servers.SetVPNState("connecting")
			return a, SpinnerTickCmd()
		case vpn.StateConnected:
			if a.conn != nil {
				a.status.SetConnected(a.conn.Info())
			}
			a.servers.SetVPNState("connected")
			return a, TickCmd()
		case vpn.StateDisconnected:
			a.conn = nil
			a.status.SetDisconnected()
			a.servers.SetVPNState("disconnected")
			a.view = ViewServers
			return a, nil
		}

	case daemonEventMsg:
		return a.handleDaemonEvent(msg.Event)

	case connectErrorMsg:
		a.status.SetError(msg.Err)
		return a, nil

	case DisconnectedMsg:
		a.conn = nil
		a.status.SetDisconnected()
		a.servers.SetVPNState("disconnected")
		a.servers.SetConnectedServer("")
		a.view = ViewServers
		return a, nil

	case daemonStatusMsg:
		a.status.SetFromDaemonStatus(msg.data)
		if msg.data.State == "Connected" {
			return a, TickCmd()
		}
		return a, nil

	case accountInfoMsg:
		a.settings.SetAccountInfo(msg.username, msg.planName)
		return a, nil

	case LogoutMsg:
		a.authenticated = false
		a.vpnInfo = nil
		a.serverList = nil
		a.conn = nil
		a.view = ViewLogin
		a.login = NewLoginModel()
		a.login.SetSize(a.width, a.height)
		return a, a.login.Init()
	}

	var cmd tea.Cmd
	switch a.view {
	case ViewLogin:
		if a.daemonMode {
			a.login, cmd = a.login.UpdateDaemon(msg, a.daemonClient)
		} else {
			a.login, cmd = a.login.Update(msg, a.client, a.store)
		}
		cmds = append(cmds, cmd)
	case ViewServers:
		a.servers, cmd = a.servers.Update(msg, a.cfg)
		cmds = append(cmds, cmd)
	case ViewStatus:
		if a.daemonMode {
			a.status, cmd = a.status.UpdateDaemon(msg, a.daemonClient)
		} else {
			a.status, cmd = a.status.Update(msg, a.conn)
		}
		cmds = append(cmds, cmd)
	case ViewSettings:
		a.settings, cmd = a.settings.Update(msg, a.cfg, a.daemonClient)
		cmds = append(cmds, cmd)
	}

	return a, tea.Batch(cmds...)
}

func (a App) View() string {
	if a.width == 0 {
		return ""
	}

	var content string
	switch a.view {
	case ViewLoading:
		content = lipgloss.Place(a.width, a.height,
			lipgloss.Center, lipgloss.Center,
			StyleBox.Width(40).Render(
				lipgloss.JoinVertical(lipgloss.Left,
					lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render("pVPN"),
					"",
					StyleDim.Render("Connecting..."),
				),
			),
		)
	case ViewLogin:
		content = a.login.View()
	case ViewServers:
		content = a.servers.View()
	case ViewStatus:
		content = a.status.View()
	case ViewSettings:
		content = a.settings.ViewWithConfig(a.cfg)
	}

	if a.authenticated && a.view != ViewLogin && a.view != ViewLoading {
		nav := a.renderNav("")
		return lipgloss.JoinVertical(lipgloss.Left, nav, content)
	}

	return content
}

func (a App) renderNav(extra string) string {
	brand := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorPrimary).
		Padding(0, 1).
		Render("pVPN")

	tabs := []struct {
		key   string
		label string
		view  View
	}{
		{"1", "Status", ViewStatus},
		{"2", "Servers", ViewServers},
		{"3", "Settings", ViewSettings},
	}

	activeTab := lipgloss.NewStyle().
		Foreground(ColorFg).
		Bold(true).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent)

	inactiveTab := lipgloss.NewStyle().
		Foreground(ColorFgDim).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder)

	var parts []string
	for _, t := range tabs {
		label := fmt.Sprintf("%s %s", t.key, t.label)
		if a.view == t.view {
			parts = append(parts, activeTab.Render(label))
		} else {
			parts = append(parts, inactiveTab.Render(label))
		}
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Center, parts...)
	nav := lipgloss.JoinHorizontal(lipgloss.Center, brand, "  ", tabBar, extra)
	return lipgloss.NewStyle().
		Width(a.width).
		Render(nav)
}

func joinWith(items []string, sep string) []string {
	if len(items) == 0 {
		return nil
	}
	result := []string{items[0]}
	for _, item := range items[1:] {
		result = append(result, sep, item)
	}
	return result
}

// --- Standalone mode functions ---

func (a App) loadServers() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		resp, err := a.client.GetServers(ctx)
		if err != nil {
			return serversLoadedMsg{Err: err}
		}
		return serversLoadedMsg{Servers: resp.LogicalServers}
	}
}

func connectToServer(client *api.Client, cfg *config.Config, server *api.LogicalServer) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		dnsBackend, err := network.DetectBackend()
		if err != nil {
			return connectErrorMsg{Err: fmt.Errorf("detect network backend: %w", err)}
		}

		kp, err := api.GenerateKeyPair()
		if err != nil {
			return connectErrorMsg{Err: fmt.Errorf("generate keys: %w", err)}
		}

		certFeatures := api.CertificateFeatures{
			NetShieldLevel: cfg.Features.NetShield,
			SplitTCP:       cfg.Features.VPNAccelerator,
			RandomNAT:      !cfg.Features.ModerateNAT,
			PortForwarding: cfg.Features.PortForwarding,
		}

		cert, err := client.RequestCert(ctx, kp, certFeatures)
		if err != nil {
			return connectErrorMsg{Err: fmt.Errorf("request certificate: %w", err)}
		}

		conn := vpn.NewConnection(client, dnsBackend)
		conn.EnableReconnect(cfg.Connection.Reconnect)

		if err := conn.Connect(ctx, server, kp, cert, certFeatures, cfg.Connection.KillSwitch, cfg.Connection.Protocol, cfg.DNS.CustomDNS); err != nil {
			return connectErrorMsg{Err: err}
		}

		cfg.Reload()
		cfg.Server.LastServer = server.Name
		cfg.Server.LastCountry = server.ExitCountry
		cfg.AddHistory(server.Name)
		cfg.Save()

		return ConnectedMsg{Info: conn.Info(), Conn: conn}
	}
}

// --- Daemon mode functions ---

func (a *App) startDaemonEvents() {
	if a.daemonClient == nil {
		return
	}
	a.daemonClient.EventHandler = func(evt *ipc.Event) {
		if globalProgram != nil {
			globalProgram.Send(daemonEventMsg{Event: evt})
		}
	}
}

func (a App) handleDaemonEvent(evt *ipc.Event) (tea.Model, tea.Cmd) {
	switch evt.Type {
	case "state-changed":
		var data ipc.StateChangedData
		json.Unmarshal(evt.Data, &data)
		switch data.State {
		case "Connecting":
			if a.view != ViewStatus {
				a.view = ViewStatus
				a.status = NewStatusModel()
				a.status.SetSize(a.width, a.contentHeight())
			}
			a.status.SetConnecting(data.Server, data.Country)
			a.servers.SetVPNState("connecting")
			return a, SpinnerTickCmd()
		case "Connected":
			a.status.SetConnectedDaemon(data.Server, data.Country)
			a.servers.SetVPNState("connected")
			a.servers.SetConnectedServer(data.Server)
			return a, TickCmd()
		case "Reconnecting":
			a.view = ViewStatus
			a.status.SetReconnecting()
			a.servers.SetVPNState("connecting")
			return a, SpinnerTickCmd()
		case "Disconnected":
			a.status.SetDisconnected()
			a.servers.SetVPNState("disconnected")
			a.servers.SetConnectedServer("")
			a.view = ViewServers
			return a, nil
		case "error":
			a.status.SetError(fmt.Errorf("%s", data.Error))
			return a, nil
		}
	case "stats-update":
		var data ipc.StatsUpdateData
		json.Unmarshal(evt.Data, &data)
		a.status.SetDaemonStats(data.RxBytes, data.TxBytes, data.Handshake)
	case "log":
		// Could show in a log panel
	}
	return a, nil
}

func (a App) loadServersDaemon() tea.Cmd {
	dc := a.daemonClient
	return func() tea.Msg {
		data, err := dc.Servers()
		if err != nil {
			return serversLoadedMsg{Err: err}
		}
		var servers []api.LogicalServer
		for _, s := range data.Servers {
			servers = append(servers, api.LogicalServer{
				Name:        s.Name,
				ExitCountry: s.Country,
				City:        s.City,
				Load:        s.Load,
				Tier:        s.Tier,
				Features:    s.Features,
				Status:      boolToStatus(s.Online),
			})
		}
		return serversLoadedMsg{Servers: servers}
	}
}

func (a App) connectDaemon(server *api.LogicalServer) tea.Cmd {
	dc := a.daemonClient
	name := server.Name
	return func() tea.Msg {
		if err := dc.Connect(name, ""); err != nil {
			return connectErrorMsg{Err: err}
		}
		return nil // state changes come via events
	}
}

type accountInfoMsg struct {
	username string
	planName string
}

type daemonStatusMsg struct{ data *ipc.StatusData }

func (a App) fetchAccountInfo() tea.Cmd {
	dc := a.daemonClient
	return func() tea.Msg {
		status, err := dc.Status()
		if err != nil {
			return nil
		}
		return accountInfoMsg{username: status.Username, planName: status.PlanName}
	}
}

func (a App) pollDaemonStatus() tea.Cmd {
	dc := a.daemonClient
	return func() tea.Msg {
		status, err := dc.Status()
		if err != nil {
			return nil
		}
		return daemonStatusMsg{data: status}
	}
}

func boolToStatus(online bool) int {
	if online {
		return 1
	}
	return 0
}
