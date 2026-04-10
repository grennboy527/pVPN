package tui

import (
	"fmt"
	"strings"

	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/YourDoritos/pvpn/internal/ipc"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type settingItem struct {
	label   string
	key     string
	kind    string // "bool", "choice", "dns", "action"
	choices []string
}

var settingItems = []settingItem{
	{label: "Protocol", key: "protocol", kind: "choice", choices: []string{"Smart", "WireGuard", "Stealth"}},
	{label: "Kill Switch", key: "killswitch", kind: "bool"},
	{label: "VPN Accelerator", key: "vpn_accelerator", kind: "bool"},
	{label: "Moderate NAT", key: "moderate_nat", kind: "bool"},
	{label: "Port Forwarding", key: "port_forwarding", kind: "bool"},
	{label: "NetShield", key: "netshield", kind: "choice", choices: []string{"Off", "Malware", "Malware+Ads+Trackers"}},
	{label: "Auto Reconnect", key: "reconnect", kind: "bool"},
	{label: "Auto Connect", key: "auto_connect", kind: "bool"},
	{label: "DNS", key: "dns", kind: "dns", choices: []string{"Proton", "Custom"}},
	{label: "", key: "separator", kind: "separator"},
	{label: "Account", key: "logout", kind: "action"},
}

// LogoutMsg signals the app to return to the login screen.
type LogoutMsg struct{}

type SettingsModel struct {
	width, height int
	cursor        int
	saved         bool
	// DNS text input
	dnsEditing bool
	dnsInput   string
	// Account info (populated from daemon)
	username string
	planName string
}

func NewSettingsModel() SettingsModel { return SettingsModel{} }

func (m *SettingsModel) SetSize(w, h int) { m.width = w; m.height = h }

func (m *SettingsModel) SetAccountInfo(username, planName string) {
	m.username = username
	m.planName = planName
}

func (m SettingsModel) Update(msg tea.Msg, cfg *config.Config, dc *ipc.Client) (SettingsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// DNS editing mode intercepts all keys
		if m.dnsEditing {
			return m.handleDNSInput(msg, cfg)
		}

		switch msg.String() {
		case "up", "k":
			m.moveCursor(-1)
		case "down", "j":
			m.moveCursor(1)
		case "enter", " ":
			return m.handleAction(cfg, dc)
		case "left":
			m.adjustSetting(cfg, -1)
			m.saved = false
		case "right":
			m.adjustSetting(cfg, 1)
			m.saved = false
		case "s":
			if cfg != nil {
				cfg.Save()
				m.saved = true
				// Notify daemon so live settings (kill switch) take effect immediately
				if dc != nil {
					go dc.NotifySettingsChanged()
				}
			}
		}
	}
	return m, nil
}

func (m *SettingsModel) moveCursor(dir int) {
	m.cursor += dir
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(settingItems) {
		m.cursor = len(settingItems) - 1
	}
	// Skip separators
	if settingItems[m.cursor].kind == "separator" {
		m.cursor += dir
		if m.cursor < 0 {
			m.cursor = 0
		}
		if m.cursor >= len(settingItems) {
			m.cursor = len(settingItems) - 1
		}
	}
}

func (m SettingsModel) handleAction(cfg *config.Config, dc *ipc.Client) (SettingsModel, tea.Cmd) {
	item := settingItems[m.cursor]

	switch item.key {
	case "dns":
		// Toggle between Proton and Custom
		if cfg == nil {
			return m, nil
		}
		if len(cfg.DNS.CustomDNS) > 0 {
			// Switch back to Proton
			cfg.DNS.CustomDNS = nil
			m.saved = false
		} else {
			// Enter DNS editing mode
			m.dnsEditing = true
			m.dnsInput = ""
		}
		return m, nil
	case "logout":
		if dc != nil {
			return m, func() tea.Msg {
				dc.Logout()
				return LogoutMsg{}
			}
		}
		return m, nil
	default:
		m.toggleSetting(cfg)
		m.saved = false
	}
	return m, nil
}

func (m SettingsModel) handleDNSInput(msg tea.KeyMsg, cfg *config.Config) (SettingsModel, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Parse and save DNS servers
		input := strings.TrimSpace(m.dnsInput)
		if input != "" && cfg != nil {
			servers := parseDNSInput(input)
			if len(servers) > 0 {
				cfg.DNS.CustomDNS = servers
				m.saved = false
			}
		}
		m.dnsEditing = false
		m.dnsInput = ""
	case "esc", "escape":
		m.dnsEditing = false
		m.dnsInput = ""
	case "backspace":
		if len(m.dnsInput) > 0 {
			m.dnsInput = m.dnsInput[:len(m.dnsInput)-1]
		}
	default:
		ch := msg.String()
		if len(ch) == 1 {
			m.dnsInput += ch
		}
	}
	return m, nil
}

func parseDNSInput(input string) []string {
	// Accept comma or space separated IPs
	input = strings.ReplaceAll(input, ",", " ")
	parts := strings.Fields(input)
	var servers []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			servers = append(servers, p)
		}
	}
	return servers
}

func (m *SettingsModel) toggleSetting(cfg *config.Config) {
	if cfg == nil {
		return
	}
	item := settingItems[m.cursor]
	if item.kind == "separator" || item.kind == "action" {
		return
	}
	switch item.key {
	case "protocol":
		switch cfg.Connection.Protocol {
		case "smart":
			cfg.Connection.Protocol = "wireguard"
		case "wireguard":
			cfg.Connection.Protocol = "stealth"
		default:
			cfg.Connection.Protocol = "smart"
		}
	case "killswitch":
		cfg.Connection.KillSwitch = !cfg.Connection.KillSwitch
	case "vpn_accelerator":
		cfg.Features.VPNAccelerator = !cfg.Features.VPNAccelerator
	case "moderate_nat":
		cfg.Features.ModerateNAT = !cfg.Features.ModerateNAT
	case "port_forwarding":
		cfg.Features.PortForwarding = !cfg.Features.PortForwarding
	case "netshield":
		cfg.Features.NetShield = (cfg.Features.NetShield + 1) % 3
	case "reconnect":
		cfg.Connection.Reconnect = !cfg.Connection.Reconnect
	case "auto_connect":
		cfg.Connection.AutoConnect = !cfg.Connection.AutoConnect
	}
}

func (m *SettingsModel) adjustSetting(cfg *config.Config, dir int) {
	if cfg == nil {
		return
	}
	item := settingItems[m.cursor]
	if item.kind == "separator" || item.kind == "action" {
		return
	}
	switch item.key {
	case "netshield":
		v := cfg.Features.NetShield + dir
		if v < 0 {
			v = 2
		}
		cfg.Features.NetShield = v % 3
	case "protocol":
		protos := []string{"smart", "wireguard", "stealth"}
		idx := 0
		for i, p := range protos {
			if cfg.Connection.Protocol == p {
				idx = i
				break
			}
		}
		idx += dir
		if idx < 0 {
			idx = len(protos) - 1
		}
		cfg.Connection.Protocol = protos[idx%len(protos)]
	case "dns":
		// Toggle between Proton and Custom via left/right
		if cfg != nil {
			if len(cfg.DNS.CustomDNS) > 0 {
				cfg.DNS.CustomDNS = nil
				m.saved = false
			} else {
				m.dnsEditing = true
				m.dnsInput = ""
			}
		}
	}
}

func (m SettingsModel) ViewWithConfig(cfg *config.Config) string {
	title := StyleTitle.Render("Settings")

	var rows []string
	for i, item := range settingItems {
		if item.kind == "separator" {
			rows = append(rows, "")
			continue
		}

		var line string
		if item.key == "logout" {
			line = m.renderAccountRow()
		} else {
			value := getSettingValue(cfg, item, m.dnsEditing && m.cursor == i, m.dnsInput)
			line = fmt.Sprintf("%-20s  %s", item.label, value)
		}

		if i == m.cursor {
			rows = append(rows, StyleSelected.Render("> "+line))
		} else {
			rows = append(rows, StyleNormal.Render("  "+line))
		}
	}

	var statusLine string
	if m.saved {
		statusLine = StyleSuccess.Render("Settings saved!")
	}

	helpText := "j/k: navigate  enter/space: toggle  left/right: adjust  s: save"
	if m.dnsEditing {
		helpText = "Type DNS IPs (comma/space separated)  enter: confirm  esc: cancel"
	}
	help := StyleHelp.Render(helpText)

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "",
		lipgloss.JoinVertical(lipgloss.Left, rows...), "",
		statusLine, "",
		help,
	)

	box := StyleBox.Width(60).Render(content)
	return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center, box)
}

func (m SettingsModel) renderAccountRow() string {
	if m.username == "" {
		return fmt.Sprintf("%-20s  %s", "Account", StyleDim.Render("not logged in"))
	}
	obfuscated := obfuscateUsername(m.username)
	plan := m.planName
	if plan == "" {
		plan = "Unknown"
	}
	return fmt.Sprintf("%-20s  %s  %s  %s",
		"Account",
		StyleValue.Render(obfuscated),
		StyleDim.Render("("+plan+")"),
		StyleWarning.Render("[enter to logout]"))
}

func obfuscateUsername(username string) string {
	if len(username) <= 6 {
		return username
	}
	show := 3
	if len(username) > 12 {
		show = 4
	}
	hidden := len(username) - show*2
	if hidden < 1 {
		hidden = 1
	}
	return username[:show] + strings.Repeat("*", hidden) + username[len(username)-show:]
}

func getSettingValue(cfg *config.Config, item settingItem, editing bool, dnsInput string) string {
	if cfg == nil {
		return StyleDim.Render("?")
	}
	switch item.key {
	case "protocol":
		idx := 0
		switch cfg.Connection.Protocol {
		case "wireguard":
			idx = 1
		case "stealth":
			idx = 2
		}
		return choiceValue(idx, item.choices)
	case "killswitch":
		return boolValue(cfg.Connection.KillSwitch)
	case "vpn_accelerator":
		return boolValue(cfg.Features.VPNAccelerator)
	case "moderate_nat":
		return boolValue(cfg.Features.ModerateNAT)
	case "port_forwarding":
		return boolValue(cfg.Features.PortForwarding)
	case "netshield":
		return choiceValue(cfg.Features.NetShield, item.choices)
	case "reconnect":
		return boolValue(cfg.Connection.Reconnect)
	case "auto_connect":
		return boolValue(cfg.Connection.AutoConnect)
	case "dns":
		if editing {
			cursor := lipgloss.NewStyle().Foreground(ColorAccent).Render("|")
			return StyleValue.Render(dnsInput) + cursor
		}
		if len(cfg.DNS.CustomDNS) > 0 {
			return StyleValue.Render(strings.Join(cfg.DNS.CustomDNS, ", "))
		}
		return StyleDim.Render("Proton (10.2.0.1)")
	}
	return "?"
}

func boolValue(v bool) string {
	if v {
		return StyleSuccess.Render("ON")
	}
	return StyleDim.Render("OFF")
}

func choiceValue(idx int, choices []string) string {
	if idx < 0 || idx >= len(choices) {
		return "?"
	}
	return StyleValue.Render(choices[idx])
}
