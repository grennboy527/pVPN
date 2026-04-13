package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Connection.Protocol != "smart" {
		t.Errorf("default protocol = %q, want %q", cfg.Connection.Protocol, "smart")
	}
	if cfg.Connection.DefaultPort != 51820 {
		t.Errorf("default port = %d, want %d", cfg.Connection.DefaultPort, 51820)
	}
	if !cfg.Connection.KillSwitch {
		t.Error("default killswitch should be true")
	}
	if cfg.Connection.AutoConnect {
		t.Error("default auto_connect should be false")
	}
	if !cfg.Connection.Reconnect {
		t.Error("default reconnect should be true")
	}
	if cfg.Features.NetShield != 0 {
		t.Errorf("default netshield = %d, want 0", cfg.Features.NetShield)
	}
	if !cfg.Features.VPNAccelerator {
		t.Error("default vpn_accelerator should be true")
	}
	if cfg.Features.ModerateNAT {
		t.Error("default moderate_nat should be false")
	}
	if cfg.Features.PortForwarding {
		t.Error("default port_forwarding should be false")
	}
	if cfg.Server.DefaultCountry != "" {
		t.Errorf("default country = %q, want empty", cfg.Server.DefaultCountry)
	}
	if len(cfg.Server.History) != 0 {
		t.Errorf("default history length = %d, want 0", len(cfg.Server.History))
	}
	if len(cfg.DNS.CustomDNS) != 0 {
		t.Errorf("default custom_dns length = %d, want 0", len(cfg.DNS.CustomDNS))
	}
}

// setTestPaths overrides the package-level config/data dirs to point at a temp
// dir, and creates the directories so Save/Load work without root.
func setTestPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	cfgDir := filepath.Join(dir, "config")
	datDir := filepath.Join(dir, "data")
	os.MkdirAll(cfgDir, 0750)
	os.MkdirAll(datDir, 0750)

	oldCfg, oldDat := configDir, dataDir
	configDir = cfgDir
	dataDir = datDir
	t.Cleanup(func() {
		configDir = oldCfg
		dataDir = oldDat
	})
	return dir
}

func TestLoadNonExistentReturnsDefaults(t *testing.T) {
	setTestPaths(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	def := DefaultConfig()
	if cfg.Connection.Protocol != def.Connection.Protocol {
		t.Errorf("protocol = %q, want default %q", cfg.Connection.Protocol, def.Connection.Protocol)
	}
	if cfg.Connection.DefaultPort != def.Connection.DefaultPort {
		t.Errorf("port = %d, want default %d", cfg.Connection.DefaultPort, def.Connection.DefaultPort)
	}
}

func TestSaveAndLoad(t *testing.T) {
	setTestPaths(t)

	cfg := DefaultConfig()
	cfg.Connection.Protocol = "wireguard"
	cfg.Connection.KillSwitch = false
	cfg.Features.NetShield = 2
	cfg.Server.DefaultCountry = "CH"
	cfg.Server.LastServer = "CH#10"
	cfg.Server.History = []string{"CH#10", "US#5"}
	cfg.DNS.CustomDNS = []string{"1.1.1.1", "8.8.8.8"}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.Connection.Protocol != "wireguard" {
		t.Errorf("protocol = %q, want %q", loaded.Connection.Protocol, "wireguard")
	}
	if loaded.Connection.KillSwitch {
		t.Error("killswitch should be false after load")
	}
	if loaded.Features.NetShield != 2 {
		t.Errorf("netshield = %d, want 2", loaded.Features.NetShield)
	}
	if loaded.Server.DefaultCountry != "CH" {
		t.Errorf("default_country = %q, want %q", loaded.Server.DefaultCountry, "CH")
	}
	if loaded.Server.LastServer != "CH#10" {
		t.Errorf("last_server = %q, want %q", loaded.Server.LastServer, "CH#10")
	}
	if len(loaded.Server.History) != 2 {
		t.Fatalf("history length = %d, want 2", len(loaded.Server.History))
	}
	if loaded.Server.History[0] != "CH#10" || loaded.Server.History[1] != "US#5" {
		t.Errorf("history = %v, want [CH#10 US#5]", loaded.Server.History)
	}
	if len(loaded.DNS.CustomDNS) != 2 {
		t.Fatalf("custom_dns length = %d, want 2", len(loaded.DNS.CustomDNS))
	}
}

func TestLoadMalformedTOML(t *testing.T) {
	setTestPaths(t)

	if err := EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs() error: %v", err)
	}
	path := ConfigFile()
	if err := os.WriteFile(path, []byte("{{invalid toml"), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for malformed TOML, got nil")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("error = %q, want it to contain 'parse config'", err.Error())
	}
}

func TestAddHistory_Basic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AddHistory("CH#1")
	cfg.AddHistory("US#5")

	if len(cfg.Server.History) != 2 {
		t.Fatalf("history length = %d, want 2", len(cfg.Server.History))
	}
	if cfg.Server.History[0] != "US#5" {
		t.Errorf("history[0] = %q, want %q", cfg.Server.History[0], "US#5")
	}
	if cfg.Server.History[1] != "CH#1" {
		t.Errorf("history[1] = %q, want %q", cfg.Server.History[1], "CH#1")
	}
}

func TestAddHistory_Deduplication(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AddHistory("CH#1")
	cfg.AddHistory("US#5")
	cfg.AddHistory("CH#1") // re-add existing entry

	if len(cfg.Server.History) != 2 {
		t.Fatalf("history length = %d, want 2 (dedup)", len(cfg.Server.History))
	}
	if cfg.Server.History[0] != "CH#1" {
		t.Errorf("history[0] = %q, want %q (moved to front)", cfg.Server.History[0], "CH#1")
	}
	if cfg.Server.History[1] != "US#5" {
		t.Errorf("history[1] = %q, want %q", cfg.Server.History[1], "US#5")
	}
}

func TestAddHistory_MaxLength(t *testing.T) {
	cfg := DefaultConfig()
	// Add 12 unique entries
	for i := 0; i < 12; i++ {
		cfg.AddHistory(strings.Repeat("S", i+1))
	}
	if len(cfg.Server.History) != 10 {
		t.Errorf("history length = %d, want 10 (max)", len(cfg.Server.History))
	}
	// Most recent should be first
	if cfg.Server.History[0] != "SSSSSSSSSSSS" {
		t.Errorf("history[0] = %q, want the 12th entry", cfg.Server.History[0])
	}
}

func TestAddHistory_DeduplicationAtMax(t *testing.T) {
	cfg := DefaultConfig()
	// Fill to max with unique entries
	for i := 1; i <= 10; i++ {
		cfg.AddHistory(strings.Repeat("X", i))
	}
	if len(cfg.Server.History) != 10 {
		t.Fatalf("history length = %d, want 10", len(cfg.Server.History))
	}

	// Re-add the oldest entry (should move to front, no increase in length)
	cfg.AddHistory("X")
	if len(cfg.Server.History) != 10 {
		t.Errorf("history length = %d, want 10 after dedup at max", len(cfg.Server.History))
	}
	if cfg.Server.History[0] != "X" {
		t.Errorf("history[0] = %q, want %q", cfg.Server.History[0], "X")
	}
}

func TestFilterPersistence(t *testing.T) {
	setTestPaths(t)

	cfg := DefaultConfig()
	cfg.Server.FilterTor = true
	cfg.Server.FilterStreaming = false
	cfg.Server.FilterSecureCore = true
	cfg.Server.FilterP2P = true

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !loaded.Server.FilterTor {
		t.Error("filter_tor should be true after load")
	}
	if loaded.Server.FilterStreaming {
		t.Error("filter_streaming should be false after load")
	}
	if !loaded.Server.FilterSecureCore {
		t.Error("filter_secure_core should be true after load")
	}
	if !loaded.Server.FilterP2P {
		t.Error("filter_p2p should be true after load")
	}
}

func TestConfigFilePermissions(t *testing.T) {
	setTestPaths(t)

	cfg := DefaultConfig()
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(ConfigFile())
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	perm := info.Mode().Perm()
	// The requested mode is 0660, but umask (typically 022) may reduce it.
	// In production the daemon calls FixFileOwnership to chmod 0660.
	// Here we just verify group-readable (at least 0640).
	if perm&0040 == 0 {
		t.Errorf("config file permissions = %o, want group-readable", perm)
	}
}

func TestSaveToExistingDirectories(t *testing.T) {
	setTestPaths(t)

	cfg := DefaultConfig()
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if _, err := os.Stat(ConfigDir()); os.IsNotExist(err) {
		t.Error("config directory was not created")
	}
}

func TestPartialTOMLLoad(t *testing.T) {
	setTestPaths(t)

	if err := EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs() error: %v", err)
	}

	// Write a partial config -- only connection section
	partial := `[connection]
protocol = "stealth"
default_port = 443
`
	if err := os.WriteFile(ConfigFile(), []byte(partial), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Overridden values
	if cfg.Connection.Protocol != "stealth" {
		t.Errorf("protocol = %q, want %q", cfg.Connection.Protocol, "stealth")
	}
	if cfg.Connection.DefaultPort != 443 {
		t.Errorf("port = %d, want 443", cfg.Connection.DefaultPort)
	}

	// Defaults should still apply for unspecified fields
	if !cfg.Features.VPNAccelerator {
		t.Error("vpn_accelerator should default to true for partial config")
	}
	if !cfg.Connection.KillSwitch {
		t.Error("killswitch should default to true for partial config")
	}
}
