package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/YourDoritos/pvpn/internal/ipc"
)

// version is injected at build time via -ldflags "-X main.version=...".
// Defaults to "dev" for local builds without the flag.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Handle version/help before dialing the daemon so they work even
	// when pvpnd isn't running.
	switch os.Args[1] {
	case "-v", "--version", "version":
		fmt.Printf("pvpnctl %s\n", version)
		return
	case "-h", "--help", "help":
		usage()
		return
	}

	client, err := ipc.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to pvpnd: %v\n", err)
		fmt.Fprintf(os.Stderr, "Is the daemon running? Start it with: sudo pvpnd\n")
		os.Exit(1)
	}
	defer client.Close()

	switch os.Args[1] {
	case "status":
		cmdStatus(client)
	case "connect":
		cmdConnect(client)
	case "disconnect":
		cmdDisconnect(client)
	case "servers":
		cmdServers(client)
	case "login":
		cmdLogin(client)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Usage: pvpnctl <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  status                  Show VPN connection status")
	fmt.Println("  connect [server]        Connect to a server (name, country, or 'fastest')")
	fmt.Println("  disconnect              Disconnect from VPN")
	fmt.Println("  servers                 List available servers")
	fmt.Println("  login <user> <pass>     Login to Proton account")
	fmt.Println("  version                 Print pvpnctl version and exit")
	fmt.Println("  help                    Show this help message")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --protocol <p>          Protocol: smart, wireguard, stealth")
	fmt.Println("  --format waybar         Output status in waybar JSON format")
	fmt.Println("  -v, --version           Print version and exit")
	fmt.Println("  -h, --help              Show this help message")
}

func cmdStatus(client *ipc.Client) {
	status, err := client.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check for waybar format
	for _, arg := range os.Args[2:] {
		if arg == "--format" || arg == "waybar" {
			outputWaybar(status)
			return
		}
	}

	switch status.State {
	case "Connected":
		fmt.Printf("Status:   Connected\n")
		fmt.Printf("Server:   %s\n", status.Server)
		fmt.Printf("Country:  %s\n", status.Country)
		fmt.Printf("IP:       %s\n", status.ServerIP)
		fmt.Printf("Protocol: %s\n", status.Protocol)
		fmt.Printf("Duration: %s\n", formatDuration(status.Duration))
		fmt.Printf("Upload:   %s\n", formatBytes(status.TxBytes))
		fmt.Printf("Download: %s\n", formatBytes(status.RxBytes))
	case "Connecting", "Reconnecting":
		fmt.Printf("Status: %s...\n", status.State)
		if status.Server != "" {
			fmt.Printf("Server: %s\n", status.Server)
		}
	case "not_authenticated":
		fmt.Println("Status: Not logged in")
		fmt.Println("Run: pvpnctl login <username> <password>")
	default:
		fmt.Printf("Status: %s\n", status.State)
	}
}

func outputWaybar(status *ipc.StatusData) {
	wb := map[string]interface{}{
		"text":    "",
		"tooltip": "pVPN: Disconnected",
		"class":   "disconnected",
	}

	switch status.State {
	case "Connected":
		wb["text"] = fmt.Sprintf("󰌾 %s", status.Country)
		wb["tooltip"] = fmt.Sprintf("pVPN: %s (%s)\n%s | ↑%s ↓%s",
			status.Server, status.Protocol,
			formatDuration(status.Duration),
			formatBytes(status.TxBytes), formatBytes(status.RxBytes))
		wb["class"] = "connected"
	case "Connecting", "Reconnecting":
		wb["text"] = "󰌾 ..."
		wb["tooltip"] = fmt.Sprintf("pVPN: %s", status.State)
		wb["class"] = "connecting"
	case "Disconnected":
		wb["text"] = "󰦞"
		wb["tooltip"] = "pVPN: Disconnected"
		wb["class"] = "disconnected"
	}

	data, _ := json.Marshal(wb)
	fmt.Println(string(data))
}

func cmdConnect(client *ipc.Client) {
	server := "fastest"
	protocol := ""

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--protocol":
			if i+1 < len(args) {
				protocol = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				server = args[i]
			}
		}
	}

	fmt.Printf("Connecting to %s...\n", server)
	if err := client.Connect(server, protocol); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connection initiated. Use 'pvpnctl status' to check.")
}

func cmdDisconnect(client *ipc.Client) {
	if err := client.Disconnect(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Disconnected.")
}

func cmdServers(client *ipc.Client) {
	data, err := client.Servers()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Filter by country if specified
	country := ""
	if len(os.Args) > 2 {
		country = strings.ToUpper(os.Args[2])
	}

	fmt.Printf("%-14s %-4s %5s  %s\n", "NAME", "CC", "LOAD", "FEATURES")
	fmt.Println(strings.Repeat("-", 50))

	for _, s := range data.Servers {
		if !s.Online {
			continue
		}
		if country != "" && s.Country != country {
			continue
		}
		fmt.Printf("%-14s %-4s %4d%%  %s\n", s.Name, s.Country, s.Load, featureStr(s.Features))
	}
}

func cmdLogin(client *ipc.Client) {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: pvpnctl login <username> <password> [2fa-code]")
		os.Exit(1)
	}
	username := os.Args[2]
	password := os.Args[3]
	twoFA := ""
	if len(os.Args) > 4 {
		twoFA = os.Args[4]
	}

	if err := client.Login(username, password, twoFA); err != nil {
		if err.Error() == "2fa_required" {
			fmt.Fprintln(os.Stderr, "2FA required. Run: pvpnctl login <user> <pass> <2fa-code>")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Logged in successfully.")
}

func featureStr(features int) string {
	var parts []string
	if features&4 != 0 {
		parts = append(parts, "P2P")
	}
	if features&8 != 0 {
		parts = append(parts, "Stream")
	}
	if features&2 != 0 {
		parts = append(parts, "Tor")
	}
	if features&1 != 0 {
		parts = append(parts, "SC")
	}
	return strings.Join(parts, ",")
}

func formatDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
