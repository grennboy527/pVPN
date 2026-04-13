package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/YourDoritos/pvpn/internal/api"
	"github.com/YourDoritos/pvpn/internal/config"
	"github.com/YourDoritos/pvpn/internal/daemon"
	"github.com/YourDoritos/pvpn/internal/ipc"
)

// version is injected at build time via -ldflags "-X main.version=...".
// Defaults to "dev" for local builds without the flag.
var version = "dev"

func main() {
	// Handle version/help before the root check so unprivileged users
	// can ask which pvpnd they have installed.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version", "version":
			fmt.Printf("pvpnd %s\n", version)
			return
		case "-h", "--help", "help":
			printHelp()
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pvpnd: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Usage: pvpnd [options]")
	fmt.Println()
	fmt.Println("The pVPN daemon. Owns the WireGuard interface, routes, DNS, and")
	fmt.Println("kill switch. Must run as root (or with CAP_NET_ADMIN). Normally")
	fmt.Println("started via systemd; see dist/pvpnd.service.")
	fmt.Println()
	fmt.Println("Paths:")
	fmt.Printf("  Config:   %s\n", config.ConfigFile())
	fmt.Printf("  Data:     %s\n", config.DataDir())
	fmt.Printf("  Session:  %s\n", config.SessionFile())
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  PVPN_SOCKET     Override the IPC socket path")
	fmt.Println("                  (default: /run/pvpn/pvpn.sock)")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -v, --version   Print version and exit")
	fmt.Println("  -h, --help      Show this help message")
}

func run() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("pvpnd must run as root (or with CAP_NET_ADMIN+CAP_NET_RAW)")
	}

	log.SetPrefix("pvpnd: ")
	log.SetFlags(log.Ltime)

	if err := config.EnsureSystemDirs(); err != nil {
		return fmt.Errorf("setup directories: %w", err)
	}

	// Migrate config and session from old user-home paths (pre-v0.3.0).
	migrateFromHome()

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
		log.Printf("No saved session: %v", err)
		session = nil
	}

	client := api.NewClient(session)
	client.OnTokenRefresh = func(uid, accessToken, refreshToken string) {
		// Load the existing session first to preserve fields like
		// LoginEmail and PrivateKey that aren't part of the refresh response.
		existing, _ := store.Load()
		s := &api.Session{
			UID:          uid,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}
		if existing != nil {
			s.LoginEmail = existing.LoginEmail
			s.PrivateKey = existing.PrivateKey
		}
		if saveErr := store.Save(s); saveErr != nil {
			log.Printf("Warning: failed to persist session: %v", saveErr)
		}
	}

	d := daemon.New(cfg, client, store)

	// Handle signals for clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, shutting down...", sig)
		d.Stop()
		os.Exit(0)
	}()

	socketPath := ipc.SocketPath
	if p := os.Getenv("PVPN_SOCKET"); p != "" {
		socketPath = p
	}

	return d.Run(socketPath)
}

// migrateFromHome copies config.toml and session.enc from the old
// user-home locations (~/.config/pvpn, ~/.local/share/pvpn) to the
// new system paths (/etc/pvpn, /var/lib/pvpn). Only runs once — if
// the system files already exist, migration is skipped. Old files are
// left in place so the user can clean up manually.
func migrateFromHome() {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		return
	}

	migrations := []struct {
		oldPath string
		newPath string
	}{
		{
			filepath.Join(u.HomeDir, ".config", "pvpn", "config.toml"),
			config.ConfigFile(),
		},
		{
			filepath.Join(u.HomeDir, ".local", "share", "pvpn", "session.enc"),
			config.SessionFile(),
		},
	}

	for _, m := range migrations {
		// Skip if destination already exists
		if _, err := os.Stat(m.newPath); err == nil {
			continue
		}
		// Skip if source doesn't exist
		src, err := os.Open(m.oldPath)
		if err != nil {
			continue
		}
		dst, err := os.Create(m.newPath)
		if err != nil {
			src.Close()
			log.Printf("Migration: cannot create %s: %v", m.newPath, err)
			continue
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			os.Remove(m.newPath)
			log.Printf("Migration: cannot copy %s → %s: %v", m.oldPath, m.newPath, err)
			continue
		}
		src.Close()
		dst.Close()
		config.FixFileOwnership(m.newPath)
		log.Printf("Migrated %s → %s", m.oldPath, m.newPath)
	}
}
