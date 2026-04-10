package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const sidebarWidth = 24

const (
	cardInnerW = 16
	cardInnerH = 2
	cardOuterW = cardInnerW + 2
	cardOuterH = cardInnerH + 2
	cardGap    = 0
)

type serverViewMode int

const (
	modeGrid serverViewMode = iota
	modeServers
)

type ServersModel struct {
	width, height int

	vpnInfo    *api.VPNInfoResponse
	allServers []api.LogicalServer

	mode serverViewMode

	// Grid (country cards)
	grid        []gridEntry
	gridCursor  int
	gridCols    int
	gridScrollY int

	// Server list (drill-down into country, or search results)
	filtered    []api.LogicalServer
	listCountry string // country we drilled into (empty if search results)
	serverIdx   int
	listScrollY int

	search    textinput.Model
	searching bool

	filterTor        bool
	filterStreaming  bool
	filterSecureCore bool
	filterP2P        bool

	lastCountry     string
	vpnState        string // "disconnected", "connecting", "connected"
	connectedServer string // name of currently connected server

	loading bool
	err     error
}

type gridEntry struct {
	country string
	server  api.LogicalServer
	count   int
}

func NewServersModel(vpnInfo *api.VPNInfoResponse) ServersModel {
	search := textinput.New()
	search.Placeholder = "search..."
	search.CharLimit = 64
	search.Width = sidebarWidth - 8

	return ServersModel{
		vpnInfo:  vpnInfo,
		loading:  true,
		search:   search,
		vpnState: "disconnected",
	}
}

func (m *ServersModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	m.gridCols = m.calcCols()
}

func (m *ServersModel) SetServers(servers []api.LogicalServer) {
	m.allServers = servers
	m.loading = false
	m.rebuildGrid()
}

func (m *ServersModel) SetError(err error) { m.err = err; m.loading = false }

func (m *ServersModel) SetVPNState(state string)       { m.vpnState = state }
func (m *ServersModel) SetConnectedServer(name string) { m.connectedServer = name }

func (m *ServersModel) LoadFilters(cfg *config.Config) {
	if cfg == nil {
		return
	}
	m.filterTor = cfg.Server.FilterTor
	m.filterStreaming = cfg.Server.FilterStreaming
	m.filterSecureCore = cfg.Server.FilterSecureCore
	m.filterP2P = cfg.Server.FilterP2P
	m.lastCountry = cfg.Server.LastCountry
}

func (m *ServersModel) SaveFilters(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cfg.Server.FilterTor = m.filterTor
	cfg.Server.FilterStreaming = m.filterStreaming
	cfg.Server.FilterSecureCore = m.filterSecureCore
	cfg.Server.FilterP2P = m.filterP2P
}

func (m *ServersModel) buildFilter() api.ServerFilter {
	return api.ServerFilter{
		OnlineOnly: true,
		Tor:        m.filterTor,
		Streaming:  m.filterStreaming,
		SecureCore: m.filterSecureCore,
		P2P:        m.filterP2P,
	}
}

func (m *ServersModel) userTier() int {
	if m.vpnInfo != nil {
		return m.vpnInfo.VPN.MaxTier
	}
	return 0
}

func (m *ServersModel) rebuildGrid() {
	filter := m.buildFilter()
	accessible := api.FilterServers(m.allServers, filter, m.userTier())

	type countryInfo struct {
		best  api.LogicalServer
		count int
	}
	countries := make(map[string]*countryInfo)
	var order []string

	for _, s := range accessible {
		ci, ok := countries[s.ExitCountry]
		if !ok {
			ci = &countryInfo{best: s}
			countries[s.ExitCountry] = ci
			order = append(order, s.ExitCountry)
		}
		ci.count++
		if s.Load < ci.best.Load {
			ci.best = s
		}
	}

	m.grid = make([]gridEntry, 0, len(order))
	for _, c := range order {
		ci := countries[c]
		m.grid = append(m.grid, gridEntry{
			country: c,
			server:  ci.best,
			count:   ci.count,
		})
	}

	if m.gridCursor >= len(m.grid) {
		m.gridCursor = 0
	}
	m.gridCols = m.calcCols()
}

func (m *ServersModel) calcCols() int {
	gridW := m.width - sidebarWidth - 2
	if gridW < cardOuterW {
		return 1
	}
	cols := gridW / (cardOuterW + cardGap)
	if cols < 1 {
		cols = 1
	}
	return cols
}

func (m *ServersModel) visibleRows() int {
	h := m.height - 2 // just the info line
	rows := h / (cardOuterH + cardGap)
	if rows < 1 {
		rows = 1
	}
	return rows
}

func (m *ServersModel) visibleListRows() int {
	h := m.height - 4
	if h < 3 {
		h = 3
	}
	return h
}

// quickConnectServer finds best server for last country + filters.
// When connected, excludes the current server so "change server" picks a different one.
func (m *ServersModel) quickConnectServer() *api.LogicalServer {
	filter := m.buildFilter()
	if m.lastCountry != "" {
		filter.Country = m.lastCountry
	}
	if m.vpnState == "connected" && m.connectedServer != "" {
		filter.ExcludeName = m.connectedServer
	}
	server := api.FindFastestServer(m.allServers, filter, m.userTier())
	if server == nil && m.lastCountry != "" {
		filter.Country = ""
		server = api.FindFastestServer(m.allServers, filter, m.userTier())
	}
	return server
}

func (m *ServersModel) filterByCountry(country string) {
	f := m.buildFilter()
	f.Country = country
	m.filtered = api.FilterServers(m.allServers, f, m.userTier())
	m.listCountry = country
	m.serverIdx = 0
	m.listScrollY = 0
}

func (m *ServersModel) refilterList() {
	if m.listCountry != "" {
		m.filterByCountry(m.listCountry)
	}
}

// --- Update ---

func (m ServersModel) Update(msg tea.Msg, cfg *config.Config) (ServersModel, tea.Cmd) {
	var cmd tea.Cmd

	if m.searching {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc":
				m.searching = false
				m.search.Blur()
				m.search.SetValue("")
				if m.mode == modeServers && m.listCountry != "" {
					m.refilterList()
				} else {
					m.rebuildGrid()
				}
				return m, nil
			case "enter":
				m.searching = false
				m.search.Blur()
				// In grid mode with search results, select the first match
				if m.mode == modeGrid && len(m.grid) > 0 {
					m.gridCursor = 0
				}
				return m, nil
			}
		}
		m.search, cmd = m.search.Update(msg)
		m.applySearch()
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.gridCols = m.calcCols()
	case tea.KeyMsg:
		if m.mode == modeServers {
			return m.updateServerList(msg, cfg)
		}
		return m.updateGrid(msg, cfg)
	}

	return m, nil
}

func (m ServersModel) updateGrid(msg tea.KeyMsg, cfg *config.Config) (ServersModel, tea.Cmd) {
	switch msg.String() {
	case "/":
		m.searching = true
		m.search.SetValue("")
		m.search.Focus()
		return m, textinput.Blink
	case "t":
		m.filterTor = !m.filterTor
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "s":
		m.filterStreaming = !m.filterStreaming
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "c":
		m.filterSecureCore = !m.filterSecureCore
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "p":
		m.filterP2P = !m.filterP2P
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "up", "k":
		if m.gridCursor >= m.gridCols {
			m.gridCursor -= m.gridCols
		}
		m.ensureVisible()
	case "down", "j":
		if m.gridCursor+m.gridCols < len(m.grid) {
			m.gridCursor += m.gridCols
		} else if m.gridCursor < len(m.grid)-1 {
			m.gridCursor = len(m.grid) - 1
		}
		m.ensureVisible()
	case "left", "h":
		if m.gridCursor > 0 {
			m.gridCursor--
			m.ensureVisible()
		}
	case "right", "l":
		if m.gridCursor < len(m.grid)-1 {
			m.gridCursor++
			m.ensureVisible()
		}
	case "enter":
		if len(m.grid) > 0 && m.gridCursor < len(m.grid) {
			country := m.grid[m.gridCursor].country
			m.filterByCountry(country)
			m.mode = modeServers
		}
	case "q":
		if len(m.grid) > 0 && m.gridCursor < len(m.grid) {
			entry := m.grid[m.gridCursor]
			m.lastCountry = entry.country
			server := entry.server
			return m, func() tea.Msg { return ConnectRequestMsg{Server: &server} }
		}
	case "Q":
		server := m.quickConnectServer()
		if server != nil {
			s := *server
			return m, func() tea.Msg { return ConnectRequestMsg{Server: &s} }
		}
	}
	return m, nil
}

func (m ServersModel) updateServerList(msg tea.KeyMsg, cfg *config.Config) (ServersModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "backspace":
		m.mode = modeGrid
		return m, nil
	case "/":
		m.searching = true
		m.search.SetValue("")
		m.search.Focus()
		return m, textinput.Blink
	case "t":
		m.filterTor = !m.filterTor
		m.refilterList()
		m.rebuildGrid() // keep grid in sync
		m.saveAndPersist(cfg)
	case "s":
		m.filterStreaming = !m.filterStreaming
		m.refilterList()
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "c":
		m.filterSecureCore = !m.filterSecureCore
		m.refilterList()
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "p":
		m.filterP2P = !m.filterP2P
		m.refilterList()
		m.rebuildGrid()
		m.saveAndPersist(cfg)
	case "up", "k":
		if m.serverIdx > 0 {
			m.serverIdx--
			m.ensureListVisible()
		}
	case "down", "j":
		if m.serverIdx < len(m.filtered)-1 {
			m.serverIdx++
			m.ensureListVisible()
		}
	case "enter":
		if len(m.filtered) > 0 && m.serverIdx < len(m.filtered) {
			server := m.filtered[m.serverIdx]
			m.lastCountry = server.ExitCountry
			return m, func() tea.Msg { return ConnectRequestMsg{Server: &server} }
		}
	case "q":
		if len(m.filtered) > 0 {
			server := m.filtered[0]
			m.lastCountry = server.ExitCountry
			return m, func() tea.Msg { return ConnectRequestMsg{Server: &server} }
		}
	case "Q":
		server := m.quickConnectServer()
		if server != nil {
			s := *server
			return m, func() tea.Msg { return ConnectRequestMsg{Server: &s} }
		}
	}
	return m, nil
}

func (m *ServersModel) saveAndPersist(cfg *config.Config) {
	if cfg != nil {
		cfg.Reload()
	}
	m.SaveFilters(cfg)
	if cfg != nil {
		cfg.Save()
	}
}

func (m *ServersModel) ensureVisible() {
	if m.gridCols == 0 {
		return
	}
	row := m.gridCursor / m.gridCols
	visibleRows := m.visibleRows()
	if row < m.gridScrollY {
		m.gridScrollY = row
	}
	if row >= m.gridScrollY+visibleRows {
		m.gridScrollY = row - visibleRows + 1
	}
}

func (m *ServersModel) ensureListVisible() {
	vis := m.visibleListRows()
	if m.serverIdx < m.listScrollY {
		m.listScrollY = m.serverIdx
	}
	if m.serverIdx >= m.listScrollY+vis {
		m.listScrollY = m.serverIdx - vis + 1
	}
}

func (m *ServersModel) applySearch() {
	query := strings.ToLower(m.search.Value())

	if m.mode == modeServers && m.listCountry != "" {
		// Step 2: search within the drilled-into country's server list
		f := m.buildFilter()
		f.Country = m.listCountry
		all := api.FilterServers(m.allServers, f, m.userTier())
		if query == "" {
			m.filtered = all
		} else {
			m.filtered = m.filtered[:0]
			for _, s := range all {
				if strings.Contains(strings.ToLower(s.Name), query) ||
					strings.Contains(strings.ToLower(s.City), query) {
					m.filtered = append(m.filtered, s)
				}
			}
		}
		m.serverIdx = 0
		m.listScrollY = 0
		return
	}

	// Step 1: search filters country cards in the grid
	m.rebuildGrid()
	if query == "" {
		return
	}
	filtered := m.grid[:0]
	for _, g := range m.grid {
		name := countryName(g.country)
		if strings.Contains(strings.ToLower(g.country), query) ||
			strings.Contains(strings.ToLower(name), query) {
			filtered = append(filtered, g)
		}
	}
	m.grid = filtered
	if m.gridCursor >= len(m.grid) {
		m.gridCursor = 0
	}
}

// --- View ---

func (m ServersModel) View() string {
	if m.loading {
		return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center,
			StyleDim.Render("Loading servers..."))
	}
	if m.err != nil {
		return lipgloss.Place(m.width, m.height-1, lipgloss.Center, lipgloss.Center,
			StyleError.Render(fmt.Sprintf("Error: %v", m.err)))
	}

	sidebar := m.viewSidebar()
	var main string
	if m.mode == modeServers {
		main = m.viewServerList()
	} else {
		main = m.viewGrid()
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, sidebar, main)
}

func (m ServersModel) viewSidebar() string {
	w := sidebarWidth - 2

	// --- Connect button (encased, state-aware, same width as search box) ---
	boxInnerW := w - 4 // matches search box Width
	btnBase := lipgloss.NewStyle().
		Width(boxInnerW - 2). // minus padding
		Align(lipgloss.Center).
		Bold(true)

	var btnText string
	var btnBorderColor lipgloss.Color
	var btnFg lipgloss.Color
	switch m.vpnState {
	case "connecting":
		btnText = "connecting..."
		btnBorderColor = ColorWarning
		btnFg = ColorWarning
	case "connected":
		btnText = "Q change server"
		btnBorderColor = ColorSuccess
		btnFg = ColorSuccess
	default:
		btnText = "Q connect"
		btnBorderColor = ColorError
		btnFg = ColorError
	}

	connectBtn := lipgloss.NewStyle().
		Width(boxInnerW).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(btnBorderColor).
		Padding(0, 1).
		Render(btnBase.Foreground(btnFg).Render(btnText))

	// Last country below button
	var lastLine string
	if m.lastCountry != "" {
		flag := countryFlag(m.lastCountry)
		lastLine = StyleDim.Render(" last: " + flag + " " + m.lastCountry)
	}

	// --- Search box ---
	searchStyle := lipgloss.NewStyle().
		Width(w-4).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(0, 1)

	var searchBox string
	if m.searching {
		searchStyle = searchStyle.BorderForeground(ColorAccent)
		searchBox = searchStyle.Render(m.search.View())
	} else {
		searchBox = searchStyle.Render(StyleDim.Render("/ search..."))
	}

	// --- Filters ---
	filterLines := []string{StyleDim.Render("--- filters ---")}
	filters := []struct {
		key    string
		label  string
		active bool
	}{
		{"t", "Tor", m.filterTor},
		{"s", "Streaming", m.filterStreaming},
		{"c", "SecureCore", m.filterSecureCore},
		{"p", "P2P", m.filterP2P},
	}
	for _, f := range filters {
		style := StyleDim
		prefix := " "
		if f.active {
			style = StyleSelected
			prefix = "*"
		}
		filterLines = append(filterLines, style.Render(fmt.Sprintf(" %s %s %s", f.key, prefix, f.label)))
	}
	filterSection := lipgloss.JoinVertical(lipgloss.Left, filterLines...)

	// --- Nav help ---
	var navLines []string
	navLines = append(navLines, StyleDim.Render("--- nav ---"))
	navLines = append(navLines, StyleDim.Render(" j/k   move"))
	if m.mode == modeGrid {
		navLines = append(navLines, StyleDim.Render(" h/l   move"))
		navLines = append(navLines, StyleDim.Render(" enter  servers"))
		navLines = append(navLines, StyleDim.Render(" q      quick"))
		navLines = append(navLines, StyleDim.Render(" Q      last"))
	} else {
		navLines = append(navLines, StyleDim.Render(" enter  connect"))
		navLines = append(navLines, StyleDim.Render(" q      best"))
		navLines = append(navLines, StyleDim.Render(" esc    back"))
	}
	navLines = append(navLines, StyleDim.Render(" /      search"))
	navSection := lipgloss.JoinVertical(lipgloss.Left, navLines...)

	parts := []string{connectBtn}
	if lastLine != "" {
		parts = append(parts, lastLine)
	}
	parts = append(parts, "", searchBox, "", filterSection, "", navSection)

	content := lipgloss.JoinVertical(lipgloss.Left, parts...)

	return lipgloss.NewStyle().
		Width(sidebarWidth).
		Height(m.height-1).
		Padding(1, 1).
		BorderRight(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(ColorBorder).
		Render(content)
}

func (m ServersModel) viewGrid() string {
	cols := m.gridCols
	if cols == 0 {
		cols = 1
	}

	totalServers := 0
	for _, g := range m.grid {
		totalServers += g.count
	}
	info := StyleDim.Render(fmt.Sprintf(" %d servers \u00b7 %d countries", totalServers, len(m.grid)))

	visRows := m.visibleRows()
	totalRows := int(math.Ceil(float64(len(m.grid)) / float64(cols)))

	maxScroll := totalRows - visRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.gridScrollY > maxScroll {
		m.gridScrollY = maxScroll
	}
	if m.gridScrollY < 0 {
		m.gridScrollY = 0
	}

	var rows []string
	for row := m.gridScrollY; row < m.gridScrollY+visRows && row < totalRows; row++ {
		var cards []string
		for col := 0; col < cols; col++ {
			idx := row*cols + col
			if idx >= len(m.grid) {
				cards = append(cards, emptyCard())
				continue
			}
			cards = append(cards, m.renderCard(idx))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cards...))
	}

	grid := lipgloss.JoinVertical(lipgloss.Left, rows...)

	var scrollHint string
	if totalRows > visRows {
		scrollHint = StyleDim.Render(fmt.Sprintf(" [%d/%d]", m.gridScrollY+1, totalRows))
	}

	return lipgloss.NewStyle().
		Padding(0, 1).
		Render(lipgloss.JoinVertical(lipgloss.Left, info+scrollHint, grid))
}

func (m ServersModel) viewServerList() string {
	if len(m.filtered) == 0 {
		title := " No servers found"
		if m.listCountry != "" {
			flag := countryFlag(m.listCountry)
			title = fmt.Sprintf(" %s %s — no servers", flag, m.listCountry)
		}
		return lipgloss.NewStyle().Padding(1, 2).Render(StyleDim.Render(title))
	}

	country := m.filtered[0].ExitCountry
	flag := countryFlag(country)
	title := StyleTitle.Render(fmt.Sprintf(" %s %s — %d servers", flag, country, len(m.filtered)))

	visH := m.visibleListRows()
	start := m.listScrollY
	end := start + visH
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	var rows []string
	for i := start; i < end; i++ {
		s := m.filtered[i]
		rows = append(rows, m.renderServerRow(&s, i == m.serverIdx))
	}

	var scrollHint string
	if len(m.filtered) > visH {
		scrollHint = StyleDim.Render(fmt.Sprintf("  [%d/%d]", m.serverIdx+1, len(m.filtered)))
	}

	return lipgloss.NewStyle().
		Padding(0, 1).
		Render(lipgloss.JoinVertical(lipgloss.Left,
			title+scrollHint, "",
			lipgloss.JoinVertical(lipgloss.Left, rows...),
		))
}

func (m ServersModel) renderServerRow(s *api.LogicalServer, selected bool) string {
	loadColor := LoadColor(s.Load)
	loadStr := lipgloss.NewStyle().Foreground(loadColor).Render(fmt.Sprintf("%3d%%", s.Load))

	var features []string
	if s.IsP2P() {
		features = append(features, "P2P")
	}
	if s.IsStreaming() {
		features = append(features, "Stream")
	}
	if s.IsTor() {
		features = append(features, "Tor")
	}
	if s.IsSecureCore() {
		features = append(features, "SC")
	}
	featureStr := ""
	if len(features) > 0 {
		featureStr = StyleDim.Render(" [" + strings.Join(features, ",") + "]")
	}
	city := ""
	if s.City != "" {
		city = StyleDim.Render(" " + s.City)
	}

	line := fmt.Sprintf(" %-14s %s%s%s", s.Name, loadStr, city, featureStr)
	if selected {
		return StyleSelected.Render("> " + line)
	}
	return StyleNormal.Render("  " + line)
}

// --- Card rendering ---

var (
	cardBorderNormal = lipgloss.NewStyle().
				Width(cardInnerW).
				Height(cardInnerH).
				Padding(0, 1).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorBorder)

	cardBorderSelected = lipgloss.NewStyle().
				Width(cardInnerW).
				Height(cardInnerH).
				Padding(0, 1).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorAccent).
				Background(lipgloss.Color("#1a3a1a"))

	cardBorderEmpty = lipgloss.NewStyle().
			Width(cardInnerW).
			Height(cardInnerH).
			Padding(0, 1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBgLight)
)

func emptyCard() string {
	return cardBorderEmpty.Render("")
}

func (m ServersModel) renderCard(idx int) string {
	entry := m.grid[idx]
	selected := idx == m.gridCursor

	flag := countryFlag(entry.country)
	cName := countryName(entry.country)
	countText := StyleDim.Render(fmt.Sprintf("%d servers", entry.count))
	if entry.count == 1 {
		countText = StyleDim.Render("1 server")
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		fmt.Sprintf("%s %s", flag, cName),
		countText,
	)

	if selected {
		return cardBorderSelected.Render(content)
	}
	return cardBorderNormal.Render(content)
}

func countryFlag(code string) string {
	if len(code) != 2 {
		return "  "
	}
	code = strings.ToUpper(code)
	return string(rune(0x1F1E6+int(code[0])-'A')) + string(rune(0x1F1E6+int(code[1])-'A'))
}

func countryName(code string) string {
	names := map[string]string{
		"AD": "Andorra", "AE": "United Arab Emirates", "AL": "Albania", "AM": "Armenia",
		"AR": "Argentina", "AT": "Austria", "AU": "Australia", "BA": "Bosnia", "BE": "Belgium",
		"BG": "Bulgaria", "BR": "Brazil", "CA": "Canada", "CH": "Switzerland", "CL": "Chile",
		"CO": "Colombia", "CR": "Costa Rica", "CY": "Cyprus", "CZ": "Czech Republic",
		"DE": "Germany", "DK": "Denmark", "EE": "Estonia", "EG": "Egypt", "ES": "Spain",
		"FI": "Finland", "FR": "France", "GB": "United Kingdom", "GE": "Georgia", "GR": "Greece",
		"HK": "Hong Kong", "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
		"IL": "Israel", "IN": "India", "IS": "Iceland", "IT": "Italy", "JP": "Japan",
		"KH": "Cambodia", "KR": "South Korea", "KZ": "Kazakhstan", "LT": "Lithuania",
		"LU": "Luxembourg", "LV": "Latvia", "MD": "Moldova", "MK": "North Macedonia",
		"MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria", "NL": "Netherlands", "NO": "Norway",
		"NZ": "New Zealand", "PA": "Panama", "PE": "Peru", "PH": "Philippines", "PK": "Pakistan",
		"PL": "Poland", "PR": "Puerto Rico", "PT": "Portugal", "RO": "Romania", "RS": "Serbia",
		"SE": "Sweden", "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia", "TH": "Thailand",
		"TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "US": "United States", "VN": "Vietnam",
		"ZA": "South Africa",
	}
	if name, ok := names[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}
