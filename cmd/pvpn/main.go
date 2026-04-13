package main

import (
	"fmt"
	"os"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/YourDoritos/pvpn/internal/tui"
	"github.com/YourDoritos/pvpn/internal/vpn"
	tea "github.com/charmbracelet/bubbletea"
)

// version is injected at build time via -ldflags "-X main.version=...".
// Defaults to "dev" for local builds without the flag.
var version = "dev"

func main() {
	// Handle version/help before any setup so they work on a fresh
	// install with no config dir, no daemon, no session, etc.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version", "version":
			fmt.Printf("pvpn %s\n", version)
			return
		case "-h", "--help", "help":
			printHelp()
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pvpn: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Usage: pvpn [options]")
	fmt.Println()
	fmt.Println("Launches the pVPN terminal UI. Talks to the pvpnd daemon over a")
	fmt.Println("Unix socket; the daemon must be running (normally via systemd).")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -v, --version   Print version and exit")
	fmt.Println("  -h, --help      Show this help message")
	fmt.Println()
	fmt.Println("See also: pvpnctl (scriptable CLI), pvpnd (daemon).")
}

func run() error {
	if err := config.EnsureDirs(); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	store, err := api.NewSessionStore(config.SessionFile())
	if err != nil {
		return fmt.Errorf("init session store: %w", err)
	}

	session, err := store.Load()
	if err != nil {
		session = nil
	}

	client := api.NewClient(session)
	client.OnTokenRefresh = func(uid, accessToken, refreshToken string) {
		// Load existing session to preserve LoginEmail and PrivateKey
		// which aren't part of the refresh response.
		existing, _ := store.Load()
		s := &api.Session{UID: uid, AccessToken: accessToken, RefreshToken: refreshToken}
		if existing != nil {
			s.LoginEmail = existing.LoginEmail
			s.PrivateKey = existing.PrivateKey
		}
		store.Save(s)
	}

	app := tui.NewApp(client, store, cfg)
	p := tea.NewProgram(app, tea.WithAltScreen())
	tui.SetProgram(p)

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// Safety net for standalone mode only — clean up leftover VPN state.
	// In daemon mode the daemon owns the VPN lifecycle; cleaning up here
	// would nuke the kill switch while the connection is still active.
	if finalApp, ok := finalModel.(tui.App); ok && !finalApp.IsDaemonMode() {
		vpn.CleanupIfNoTunnel()
	}

	return nil
}
