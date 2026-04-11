package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
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
	fmt.Println("Environment:")
	fmt.Println("  PVPN_SOCKET     Override the IPC socket path")
	fmt.Println("                  (default: /run/pvpn/pvpn.sock)")
	fmt.Println("  SUDO_USER       Username whose ~/.config/pvpn to load config from")
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

	if err := config.EnsureDirs(); err != nil {
		return fmt.Errorf("setup directories: %w", err)
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
