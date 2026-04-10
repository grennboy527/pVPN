package tui

import "github.com/charmbracelet/lipgloss"

// Proton brand colors
var (
	ColorPrimary   = lipgloss.Color("#6D4AFF") // Proton purple
	ColorSecondary = lipgloss.Color("#8B6FFF")
	ColorAccent    = lipgloss.Color("#00F0C8") // Proton green/teal
	ColorSuccess   = lipgloss.Color("#2ECC71")
	ColorWarning   = lipgloss.Color("#F39C12")
	ColorError     = lipgloss.Color("#E74C3C")
	ColorMuted     = lipgloss.Color("#6C757D")
	ColorBg        = lipgloss.Color("#1A1A2E")
	ColorBgLight   = lipgloss.Color("#232340")
	ColorFg        = lipgloss.Color("#E8E8E8")
	ColorFgDim     = lipgloss.Color("#888899")
	ColorHighlight = lipgloss.Color("#6D4AFF")
	ColorBorder    = lipgloss.Color("#3D3D5C")
)

// Shared styles
var (
	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(ColorFgDim)

	StyleSelected = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true)

	StyleNormal = lipgloss.NewStyle().
			Foreground(ColorFg)

	StyleDim = lipgloss.NewStyle().
			Foreground(ColorFgDim)

	StyleSuccess = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	StyleError = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	StyleWarning = lipgloss.NewStyle().
			Foreground(ColorWarning)

	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2)

	StyleActiveBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(1, 2)

	StyleStatusBar = lipgloss.NewStyle().
			Foreground(ColorFg).
			Background(ColorBgLight).
			Padding(0, 1)

	StyleHelp = lipgloss.NewStyle().
			Foreground(ColorFgDim)

	StyleLabel = lipgloss.NewStyle().
			Foreground(ColorFgDim).
			Width(14)

	StyleValue = lipgloss.NewStyle().
			Foreground(ColorFg)

	StyleBadge = lipgloss.NewStyle().
			Foreground(ColorBg).
			Background(ColorPrimary).
			Padding(0, 1).
			Bold(true)

	StyleBadgeSuccess = lipgloss.NewStyle().
				Foreground(ColorBg).
				Background(ColorSuccess).
				Padding(0, 1).
				Bold(true)
)

// Feature badge for server features
func FeatureBadge(label string) string {
	return lipgloss.NewStyle().
		Foreground(ColorBg).
		Background(ColorSecondary).
		Padding(0, 1).
		Render(label)
}

// Load color based on percentage
func LoadColor(load int) lipgloss.Color {
	switch {
	case load < 50:
		return ColorSuccess
	case load < 80:
		return ColorWarning
	default:
		return ColorError
	}
}
