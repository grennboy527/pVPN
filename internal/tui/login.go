package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/ipc"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pquerna/otp/totp"
)

type loginStep int

const (
	stepUsername loginStep = iota
	stepPassword
	step2FA
	stepLogging
)

type LoginModel struct {
	width, height int
	step          loginStep
	username      textinput.Model
	password      textinput.Model
	twofa         textinput.Model
	err           error
	status        string
}

type loginDoneMsg struct {
	VPNInfo *api.VPNInfoResponse
}
type loginErrMsg struct{ err error }
type login2FAMsg struct{}

func NewLoginModel() LoginModel {
	username := textinput.New()
	username.Placeholder = "proton@email.com"
	username.CharLimit = 128
	username.Width = 40
	username.Focus()

	password := textinput.New()
	password.Placeholder = "password"
	password.EchoMode = textinput.EchoPassword
	password.EchoCharacter = '*'
	password.CharLimit = 256
	password.Width = 40

	twofa := textinput.New()
	twofa.Placeholder = "6-digit code or TOTP secret"
	twofa.CharLimit = 64
	twofa.Width = 40

	return LoginModel{
		step:     stepUsername,
		username: username,
		password: password,
		twofa:    twofa,
	}
}

func (m LoginModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m LoginModel) InputFocused() bool {
	return m.step != stepLogging
}

func (m *LoginModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// UpdateDaemon handles login via daemon IPC.
func (m LoginModel) UpdateDaemon(msg tea.Msg, dc *ipc.Client) (LoginModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			return m.handleEnterDaemon(dc)
		case "tab", "shift+tab":
			return m.handleTab()
		case "esc":
			m.err = nil
		}

	case loginDoneMsg:
		return m, func() tea.Msg { return LoginSuccessMsg(msg) }
	case loginErrMsg:
		m.err = msg.err
		m.status = ""
		if m.step == stepLogging {
			m.step = stepUsername
			m.username.Focus()
		}
		return m, nil
	case login2FAMsg:
		m.step = step2FA
		m.status = ""
		m.twofa.Focus()
		return m, textinput.Blink
	}

	switch m.step {
	case stepUsername:
		m.username, cmd = m.username.Update(msg)
	case stepPassword:
		m.password, cmd = m.password.Update(msg)
	case step2FA:
		m.twofa, cmd = m.twofa.Update(msg)
	}

	return m, cmd
}

func (m LoginModel) handleEnterDaemon(dc *ipc.Client) (LoginModel, tea.Cmd) {
	switch m.step {
	case stepUsername:
		if m.username.Value() == "" {
			return m, nil
		}
		m.step = stepPassword
		m.username.Blur()
		m.password.Focus()
		return m, textinput.Blink
	case stepPassword:
		if m.password.Value() == "" {
			return m, nil
		}
		m.step = stepLogging
		m.password.Blur()
		m.status = "Authenticating..."
		m.err = nil
		return m, m.doLoginDaemon(dc, "")
	case step2FA:
		if m.twofa.Value() == "" {
			return m, nil
		}
		m.step = stepLogging
		m.twofa.Blur()
		m.status = "Verifying 2FA..."
		return m, m.doLoginDaemon(dc, m.twofa.Value())
	}
	return m, nil
}

func (m LoginModel) doLoginDaemon(dc *ipc.Client, twoFA string) tea.Cmd {
	username := m.username.Value()
	password := m.password.Value()
	code := twoFA
	// Handle TOTP secret
	if len(code) > 6 {
		generated, err := totp.GenerateCode(code, time.Now())
		if err == nil {
			code = generated
		}
	}
	return func() tea.Msg {
		err := dc.Login(username, password, code)
		if err != nil {
			if err.Error() == "2fa_required" {
				return login2FAMsg{}
			}
			return loginErrMsg{err: err}
		}
		// Login succeeded — daemon is now authenticated
		// Return a minimal VPNInfo (daemon manages the real one)
		return loginDoneMsg{VPNInfo: &api.VPNInfoResponse{
			VPN: api.VPNInfo{MaxTier: 2, PlanTitle: "Plus"},
		}}
	}
}

func (m LoginModel) Update(msg tea.Msg, client *api.Client, store *api.SessionStore) (LoginModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			return m.handleEnter(client, store)
		case "tab", "shift+tab":
			return m.handleTab()
		case "esc":
			m.err = nil
		}

	case loginDoneMsg:
		return m, func() tea.Msg { return LoginSuccessMsg(msg) }

	case login2FAMsg:
		m.step = step2FA
		m.status = ""
		m.twofa.Focus()
		return m, textinput.Blink

	case loginErrMsg:
		m.err = msg.err
		m.status = ""
		if m.step == stepLogging {
			m.step = stepUsername
			m.username.Focus()
		}
		return m, nil
	}

	switch m.step {
	case stepUsername:
		m.username, cmd = m.username.Update(msg)
	case stepPassword:
		m.password, cmd = m.password.Update(msg)
	case step2FA:
		m.twofa, cmd = m.twofa.Update(msg)
	}

	return m, cmd
}

func (m LoginModel) handleEnter(client *api.Client, store *api.SessionStore) (LoginModel, tea.Cmd) {
	switch m.step {
	case stepUsername:
		if m.username.Value() == "" {
			return m, nil
		}
		m.step = stepPassword
		m.username.Blur()
		m.password.Focus()
		return m, textinput.Blink
	case stepPassword:
		if m.password.Value() == "" {
			return m, nil
		}
		m.step = stepLogging
		m.password.Blur()
		m.status = "Authenticating..."
		m.err = nil
		return m, m.doLogin(client, store)
	case step2FA:
		if m.twofa.Value() == "" {
			return m, nil
		}
		m.step = stepLogging
		m.twofa.Blur()
		m.status = "Verifying 2FA..."
		return m, m.do2FA(client, store)
	}
	return m, nil
}

func (m LoginModel) handleTab() (LoginModel, tea.Cmd) {
	switch m.step {
	case stepUsername:
		m.step = stepPassword
		m.username.Blur()
		m.password.Focus()
		return m, textinput.Blink
	case stepPassword:
		m.step = stepUsername
		m.password.Blur()
		m.username.Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m LoginModel) doLogin(client *api.Client, store *api.SessionStore) tea.Cmd {
	username := m.username.Value()
	password := m.password.Value()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		auth, err := client.Login(ctx, username, password)
		if err != nil {
			return loginErrMsg{err: fmt.Errorf("login: %w", err)}
		}
		if api.Needs2FA(auth) {
			return login2FAMsg{}
		}
		session := client.GetSession()
		if err := store.Save(&session); err != nil {
			return loginErrMsg{err: err}
		}
		info, err := client.GetVPNInfo(ctx)
		if err != nil {
			return loginErrMsg{err: err}
		}
		return loginDoneMsg{VPNInfo: info}
	}
}

func (m LoginModel) do2FA(client *api.Client, store *api.SessionStore) tea.Cmd {
	input := m.twofa.Value()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		code := input
		if len(input) > 6 {
			generated, err := totp.GenerateCode(input, time.Now())
			if err != nil {
				return loginErrMsg{err: fmt.Errorf("invalid TOTP secret: %w", err)}
			}
			code = generated
		}
		if err := client.Submit2FA(ctx, code); err != nil {
			return loginErrMsg{err: fmt.Errorf("2FA failed: %w", err)}
		}
		session := client.GetSession()
		if err := store.Save(&session); err != nil {
			return loginErrMsg{err: err}
		}
		info, err := client.GetVPNInfo(ctx)
		if err != nil {
			return loginErrMsg{err: err}
		}
		return loginDoneMsg{VPNInfo: info}
	}
}

func (m LoginModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render("pVPN - Proton VPN")
	subtitle := StyleDim.Render("Sign in with your Proton account")

	var fields string
	if m.step == step2FA {
		fields = lipgloss.JoinVertical(lipgloss.Left,
			StyleLabel.Render("2FA Code"),
			m.twofa.View(),
		)
	} else {
		fields = lipgloss.JoinVertical(lipgloss.Left,
			StyleLabel.Render("Email"),
			m.username.View(),
			"",
			StyleLabel.Render("Password"),
			m.password.View(),
		)
	}

	var statusLine string
	if m.err != nil {
		statusLine = StyleError.Render(m.err.Error())
	} else if m.status != "" {
		statusLine = StyleWarning.Render(m.status)
	}

	help := StyleHelp.Render("tab: switch field  enter: submit  ctrl+c: quit")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, subtitle, "", fields, "", statusLine, "", help,
	)

	box := StyleBox.Width(50).Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}
