package tui

import (
	"fmt"
	"time"

	"github.com/YourDoritos/pvpn/internal/ipc"
	"github.com/YourDoritos/pvpn/internal/vpn"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg time.Time

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type StatusModel struct {
	width, height int
	state         string
	serverName    string
	country       string
	entryCountry  string
	connectedAt   time.Time
	forwardedPort uint16
	info          vpn.ConnectionInfo
	stats         *vpn.PeerStats
	err           error
	spinnerIdx    int
}

func NewStatusModel() StatusModel {
	return StatusModel{state: "disconnected"}
}

func (m *StatusModel) SetSize(w, h int) { m.width = w; m.height = h }

func (m *StatusModel) SetConnecting(name, country string) {
	m.state = "connecting"
	m.serverName = name
	m.country = country
	m.err = nil
}

func (m *StatusModel) SetConnected(info vpn.ConnectionInfo) {
	m.state = "connected"
	m.info = info
	m.serverName = info.ServerName
	m.country = info.ServerCountry
	m.entryCountry = info.EntryCountry
	m.connectedAt = info.ConnectedAt
	m.forwardedPort = info.ForwardedPort
	m.err = nil
}

func (m *StatusModel) SetReconnecting()   { m.state = "reconnecting" }
func (m *StatusModel) SetError(err error) { m.state = "error"; m.err = err }
func (m *StatusModel) SetDisconnected() {
	m.state = "disconnected"
	m.stats = nil
	m.forwardedPort = 0
	m.entryCountry = ""
}

// Daemon mode setters
func (m *StatusModel) SetConnectedDaemon(server, country string) {
	m.state = "connected"
	m.serverName = server
	m.country = country
	m.connectedAt = time.Now()
	m.err = nil
}

func (m *StatusModel) SetConnectedFromDaemon(data *ipc.StatusData) {
	m.state = "connected"
	m.serverName = data.Server
	m.country = data.Country
	m.entryCountry = data.EntryCountry
	m.connectedAt = time.Now().Add(-time.Duration(data.Duration) * time.Second)
	m.forwardedPort = data.ForwardedPort
	m.info = vpn.ConnectionInfo{
		ServerName:    data.Server,
		ServerIP:      data.ServerIP,
		ServerCountry: data.Country,
		EntryCountry:  data.EntryCountry,
		ConnectedAt:   m.connectedAt,
		State:         vpn.StateConnected,
		ForwardedPort: data.ForwardedPort,
	}
	if data.RxBytes > 0 || data.TxBytes > 0 {
		m.stats = &vpn.PeerStats{
			RxBytes:       data.RxBytes,
			TxBytes:       data.TxBytes,
			LastHandshake: time.Unix(data.Handshake, 0),
		}
	}
}

func (m *StatusModel) SetFromDaemonStatus(data *ipc.StatusData) {
	switch data.State {
	case "Connected":
		m.SetConnectedFromDaemon(data)
	case "Connecting":
		m.SetConnecting(data.Server, data.Country)
	case "Reconnecting":
		m.SetReconnecting()
	case "Disconnected":
		m.SetDisconnected()
	}
}

func (m *StatusModel) SetDaemonStats(rx, tx, handshake int64) {
	m.stats = &vpn.PeerStats{
		RxBytes:       rx,
		TxBytes:       tx,
		LastHandshake: time.Unix(handshake, 0),
	}
}

// daemonStatsMsg carries async stats from the daemon.
type daemonStatsMsg struct {
	stats *ipc.StatusData
}

// pollDaemonStatsCmd returns a tea.Cmd that polls daemon stats without blocking.
func pollDaemonStatsCmd(dc *ipc.Client) tea.Cmd {
	return func() tea.Msg {
		status, err := dc.Status()
		if err != nil {
			return daemonStatsMsg{}
		}
		return daemonStatsMsg{stats: status}
	}
}

func TickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func SpinnerTickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// UpdateDaemon handles updates when connected to daemon via IPC.
func (m StatusModel) UpdateDaemon(msg tea.Msg, dc *ipc.Client) (StatusModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "d":
			if m.state == "connected" || m.state == "reconnecting" {
				m.state = "disconnecting"
				return m, func() tea.Msg {
					dc.Disconnect()
					return DisconnectedMsg{}
				}
			}
			if m.state == "error" || m.state == "disconnected" {
				return m, func() tea.Msg { return DisconnectedMsg{} }
			}
		case "esc", "escape":
			if m.state == "error" || m.state == "disconnected" {
				return m, func() tea.Msg { return DisconnectedMsg{} }
			}
		}
	case daemonStatsMsg:
		if msg.stats != nil {
			m.SetDaemonStats(msg.stats.RxBytes, msg.stats.TxBytes, msg.stats.Handshake)
		}
		return m, TickCmd()
	case tickMsg:
		if m.state == "connected" && dc != nil {
			// Poll daemon for stats asynchronously
			return m, pollDaemonStatsCmd(dc)
		}
		if m.state == "connecting" || m.state == "reconnecting" {
			m.spinnerIdx = (m.spinnerIdx + 1) % len(spinnerFrames)
			return m, SpinnerTickCmd()
		}
	}
	return m, nil
}

func (m StatusModel) Update(msg tea.Msg, conn *vpn.Connection) (StatusModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "d":
			if (m.state == "connected" || m.state == "reconnecting") && conn != nil {
				m.state = "disconnecting"
				return m, func() tea.Msg {
					conn.Disconnect()
					return DisconnectedMsg{}
				}
			}
			// On error/disconnected, "d" goes back to servers
			if m.state == "error" || m.state == "disconnected" {
				return m, func() tea.Msg { return DisconnectedMsg{} }
			}
		case "esc", "escape":
			// Esc on error/disconnected also goes back
			if m.state == "error" || m.state == "disconnected" {
				return m, func() tea.Msg { return DisconnectedMsg{} }
			}
		case "r":
			if m.state == "connected" && conn != nil {
				if stats, err := conn.Stats(); err == nil {
					m.stats = stats
				}
			}
		}
	case tickMsg:
		if m.state == "connected" && conn != nil {
			if stats, err := conn.Stats(); err == nil {
				m.stats = stats
			}
			return m, TickCmd()
		}
		if m.state == "connecting" || m.state == "reconnecting" {
			m.spinnerIdx = (m.spinnerIdx + 1) % len(spinnerFrames)
			return m, SpinnerTickCmd()
		}
	}
	return m, nil
}

func (m StatusModel) View() string {
	switch m.state {
	case "connecting":
		return m.viewConnecting()
	case "connected":
		return m.viewConnected()
	case "reconnecting":
		return m.viewReconnecting()
	case "error":
		return m.viewError()
	case "disconnecting":
		return m.viewDisconnecting()
	default:
		return m.viewDisconnected()
	}
}

func (m StatusModel) viewConnecting() string {
	flag := countryFlag(m.country)
	spinner := StyleWarning.Render(spinnerFrames[m.spinnerIdx])
	content := lipgloss.JoinVertical(lipgloss.Left,
		StyleTitle.Render(spinner+" Connecting..."),
		"",
		kvRow("Server", fmt.Sprintf("%s %s", flag, m.serverName)),
		"",
		StyleDim.Render("Establishing tunnel..."),
	)
	box := StyleBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m StatusModel) viewConnected() string {
	flag := countryFlag(m.country)
	badge := StyleBadgeSuccess.Render("CONNECTED")
	title := lipgloss.JoinHorizontal(lipgloss.Center, badge, "  ", m.serverName)
	duration := time.Since(m.connectedAt).Round(time.Second)

	rows := []string{
		title, "",
		kvRow("Server", fmt.Sprintf("%s %s", flag, m.serverName)),
		kvRow("Country", fmt.Sprintf("%s %s", flag, m.country)),
		kvRow("Server IP", m.info.ServerIP),
		kvRow("Duration", formatDuration(duration)),
	}

	if m.entryCountry != "" {
		rows = append(rows,
			kvRow("Route", fmt.Sprintf("%s %s -> %s %s",
				countryFlag(m.entryCountry), m.entryCountry,
				countryFlag(m.country), m.country)))
	}

	if m.forwardedPort > 0 {
		rows = append(rows, kvRow("Port Forward", fmt.Sprintf("%d (TCP+UDP)", m.forwardedPort)))
	}

	if m.stats != nil {
		rows = append(rows, "",
			StyleDim.Render("--- Traffic ---"),
			kvRow("Upload", formatBytes(m.stats.TxBytes)),
			kvRow("Download", formatBytes(m.stats.RxBytes)),
			kvRow("Handshake", m.stats.LastHandshake.Format("15:04:05")),
		)
	}

	rows = append(rows, "", StyleHelp.Render("d: disconnect  r: refresh stats"))

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)
	box := StyleActiveBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m StatusModel) viewError() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		StyleError.Render("Connection Failed"), "",
		StyleNormal.Render(m.err.Error()), "",
		StyleHelp.Render("d/esc: back to servers  2: servers  3: settings"),
	)
	box := StyleBox.Width(60).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m StatusModel) viewReconnecting() string {
	flag := countryFlag(m.country)
	spinner := StyleWarning.Render(spinnerFrames[m.spinnerIdx])
	content := lipgloss.JoinVertical(lipgloss.Left,
		StyleWarning.Render(spinner+" Reconnecting..."),
		"",
		kvRow("Server", fmt.Sprintf("%s %s", flag, m.serverName)),
		"",
		StyleDim.Render("Connection lost. Attempting to reconnect..."),
		"",
		StyleHelp.Render("d: cancel and disconnect"),
	)
	box := StyleBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m StatusModel) viewDisconnecting() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		StyleTitle.Render("Disconnecting..."), "",
		StyleDim.Render("Tearing down VPN tunnel..."),
	)
	box := StyleBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m StatusModel) viewDisconnected() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		StyleTitle.Render("Not Connected"), "",
		StyleDim.Render("Select a server to connect."), "",
		StyleHelp.Render("press 2 to browse servers"),
	)
	box := StyleBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func kvRow(label, value string) string {
	return StyleLabel.Render(label) + StyleValue.Render("  "+value)
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
