package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SocketGroup is the Unix group that gates access to config, data,
// and the IPC socket. Both the daemon and unprivileged TUI users
// must share this group.
const SocketGroup = "pvpn"

// configDir and dataDir hold the resolved paths. They default to the
// system locations and can be overridden in tests via setTestDirs.
var (
	configDir = "/etc/pvpn"
	dataDir   = "/var/lib/pvpn"
)

// ConfigDir returns the configuration directory (/etc/pvpn).
func ConfigDir() string {
	return configDir
}

// DataDir returns the data directory (/var/lib/pvpn).
func DataDir() string {
	return dataDir
}

// DebugPaths prints the resolved paths (for troubleshooting).
func DebugPaths() string {
	return fmt.Sprintf("config=%s data=%s session=%s", ConfigDir(), DataDir(), SessionFile())
}

// ConfigFile returns the path to the config file.
func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.toml")
}

// SessionFile returns the path to the encrypted session file.
func SessionFile() string {
	return filepath.Join(DataDir(), "session.enc")
}

// EnsureSystemDirs creates the config and data directories with root:pvpn
// ownership and mode 0750. Must be called as root (typically by the daemon).
// Also self-heals ownership on existing config.toml and session.enc so they
// stay root:pvpn 0660 across upgrades.
func EnsureSystemDirs() error {
	grp, err := user.LookupGroup(SocketGroup)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w (create it with: groupadd -r %s)", SocketGroup, err, SocketGroup)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q: %w", grp.Gid, err)
	}

	dirs := []string{ConfigDir(), DataDir()}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chown(dir, 0, gid); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0750); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}

	// Self-heal ownership of shared files so TUI (pvpn group) can read them
	for _, p := range []string{ConfigFile(), SessionFile()} {
		if _, err := os.Stat(p); err == nil {
			os.Chown(p, 0, gid)
			os.Chmod(p, 0660)
		}
	}

	return nil
}

// EnsureDirs verifies that the config and data directories exist and are
// readable. Called by the TUI (unprivileged). Returns a helpful error if
// directories are missing or inaccessible. Does NOT verify write access —
// the shared config file is group-writable even when the directory is not.
func EnsureDirs() error {
	for _, dir := range []string{ConfigDir(), DataDir()} {
		info, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist — is pvpnd running? (sudo systemctl start pvpnd)", dir)
		}
		if err != nil {
			return fmt.Errorf("access %s: %w — are you in the %q group?", dir, err, SocketGroup)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
	}
	return nil
}

// FixFileOwnership sets the given paths to root:pvpn with mode 0660,
// so both the daemon and users in the pvpn group can access them.
// No-op if not running as root or the pvpn group doesn't exist.
func FixFileOwnership(paths ...string) {
	fixGroupPermissions(paths...)
}

func fixGroupPermissions(paths ...string) {
	if os.Getuid() != 0 {
		return
	}
	grp, err := user.LookupGroup(SocketGroup)
	if err != nil {
		return
	}
	gid, _ := strconv.Atoi(grp.Gid)
	for _, p := range paths {
		os.Chown(p, 0, gid)
		os.Chmod(p, 0660)
	}
}
