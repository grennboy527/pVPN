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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pvpnd: %v\n", err)
		os.Exit(1)
	}
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
