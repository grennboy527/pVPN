package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the application configuration.
type Config struct {
	Connection ConnectionConfig `toml:"connection"`
	Features   FeaturesConfig   `toml:"features"`
	Server     ServerConfig     `toml:"server"`
	DNS        DNSConfig        `toml:"dns"`
}

type ConnectionConfig struct {
	Protocol    string `toml:"protocol"`     // "wireguard" | "stealth"
	DefaultPort int    `toml:"default_port"` // 51820
	KillSwitch  bool   `toml:"killswitch"`
	AutoConnect bool   `toml:"auto_connect"`
	Reconnect   bool   `toml:"reconnect"`
}

type FeaturesConfig struct {
	NetShield      int  `toml:"netshield"`       // 0=off, 1=malware, 2=malware+ads+trackers
	VPNAccelerator bool `toml:"vpn_accelerator"`
	ModerateNAT    bool `toml:"moderate_nat"`
	PortForwarding bool `toml:"port_forwarding"`
}

type ServerConfig struct {
	DefaultCountry   string   `toml:"default_country"`
	PreferP2P        bool     `toml:"prefer_p2p"`
	PreferSecureCore bool     `toml:"prefer_secure_core"`
	LastServer       string   `toml:"last_server"`
	LastCountry      string   `toml:"last_country"`
	History          []string `toml:"history"` // Last 10 connected server names
	// Persisted filter state
	FilterTor        bool `toml:"filter_tor"`
	FilterStreaming   bool `toml:"filter_streaming"`
	FilterSecureCore bool `toml:"filter_secure_core"`
	FilterP2P        bool `toml:"filter_p2p"`
}

// AddHistory adds a server to the connection history (most recent first, max 10).
func (c *Config) AddHistory(serverName string) {
	// Remove duplicate if exists
	filtered := make([]string, 0, len(c.Server.History))
	for _, h := range c.Server.History {
		if h != serverName {
			filtered = append(filtered, h)
		}
	}
	// Prepend
	c.Server.History = append([]string{serverName}, filtered...)
	if len(c.Server.History) > 10 {
		c.Server.History = c.Server.History[:10]
	}
}

type DNSConfig struct {
	CustomDNS []string `toml:"custom_dns"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Connection: ConnectionConfig{
			Protocol:    "smart",
			DefaultPort: 51820,
			KillSwitch:  true,
			AutoConnect: false,
			Reconnect:   true,
		},
		Features: FeaturesConfig{
			NetShield:      0,
			VPNAccelerator: true,
			ModerateNAT:    false,
			PortForwarding: false,
		},
		Server: ServerConfig{},
		DNS:    DNSConfig{},
	}
}

// Load reads the config from disk. If the file doesn't exist, returns defaults.
func Load() (*Config, error) {
	cfg := DefaultConfig()

	path := ConfigFile()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to disk.
func (c *Config) Save() error {
	if err := EnsureDirs(); err != nil {
		return err
	}

	path := ConfigFile()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(c); err != nil {
		return err
	}
	FixFileOwnership(path)
	return nil
}

// Reload re-reads the config from disk into this struct, picking up any
// changes made by other processes. Call this before modifying + Save()
// to avoid clobbering changes from the TUI or daemon.
func (c *Config) Reload() {
	fresh, err := Load()
	if err != nil {
		return
	}
	*c = *fresh
}
