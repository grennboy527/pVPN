package vpn

import (
	"testing"
	"time"
)

// TestStateString guards the wire format used in IPC payloads and logs.
// Clients (TUI, CLI) switch on these exact strings.
func TestStateString(t *testing.T) {
	cases := []struct {
		s    State
		want string
	}{
		{StateDisconnected, "Disconnected"},
		{StateConnecting, "Connecting"},
		{StateConnected, "Connected"},
		{StateDisconnecting, "Disconnecting"},
		{StateReconnecting, "Reconnecting"},
		{StateError, "Error"},
		{State(99), "Unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("State(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

// TestNextBackoff covers the pure backoff math used by the reconnect loop.
// This is the piece most likely to regress silently — off-by-one here means
// hammering the API or waiting forever.
func TestNextBackoff(t *testing.T) {
	const ceiling = 2 * time.Minute

	cases := []struct {
		current time.Duration
		want    time.Duration
	}{
		{2 * time.Second, 4 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 16 * time.Second},
		{60 * time.Second, 120 * time.Second},
		{90 * time.Second, 120 * time.Second},  // cap
		{120 * time.Second, 120 * time.Second}, // cap
		{200 * time.Second, 120 * time.Second}, // cap even if already over
	}
	for _, c := range cases {
		if got := nextBackoff(c.current, ceiling); got != c.want {
			t.Errorf("nextBackoff(%v, %v) = %v, want %v", c.current, ceiling, got, c.want)
		}
	}
}

// TestBackoffProgressionConverges ensures the backoff saturates at max
// within a reasonable number of steps (no infinite doubling bug).
func TestBackoffProgressionConverges(t *testing.T) {
	const ceiling = 2 * time.Minute
	cur := 2 * time.Second
	for i := 0; i < 20; i++ {
		cur = nextBackoff(cur, ceiling)
	}
	if cur != ceiling {
		t.Errorf("backoff did not converge to ceiling after 20 steps: got %v, want %v", cur, ceiling)
	}
}

// TestConnectionInitialState documents the invariant that a freshly
// constructed Connection is Disconnected and has no active tunnel.
// Constructing with nil dependencies is fine — we don't touch them.
func TestConnectionInitialState(t *testing.T) {
	c := NewConnection(nil, nil)
	if got := c.State(); got != StateDisconnected {
		t.Errorf("initial state = %v, want Disconnected", got)
	}
	if c.tunnelLink() != nil {
		t.Error("tunnelLink should be nil before Connect")
	}
	if c.tunnelIfIndex() != 0 {
		t.Errorf("tunnelIfIndex = %d, want 0", c.tunnelIfIndex())
	}
	if c.Protocol() != "" {
		t.Errorf("Protocol = %q, want empty", c.Protocol())
	}
	if got := c.ForwardedPort(); got != 0 {
		t.Errorf("ForwardedPort = %d, want 0", got)
	}
}

// TestSetStateTransitionsAndCallback verifies the onState callback fires
// exactly on setState, and that the stored state matches what was set.
func TestSetStateTransitionsAndCallback(t *testing.T) {
	c := NewConnection(nil, nil)

	var seen []State
	c.OnStateChange(func(s State) { seen = append(seen, s) })

	c.setState(StateConnecting)
	c.setState(StateConnected)
	c.setState(StateReconnecting)
	c.setState(StateConnected)
	c.setState(StateDisconnecting)
	c.setState(StateDisconnected)

	want := []State{
		StateConnecting, StateConnected, StateReconnecting,
		StateConnected, StateDisconnecting, StateDisconnected,
	}
	if len(seen) != len(want) {
		t.Fatalf("got %d callbacks, want %d: %v", len(seen), len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("callback %d: got %v, want %v", i, seen[i], want[i])
		}
	}
	if c.State() != StateDisconnected {
		t.Errorf("final state = %v, want Disconnected", c.State())
	}
}

// TestTriggerReconnectNoOpWhenNotConnected verifies that wake signals
// sent while not connected are dropped — this matters because the
// daemon fires TriggerReconnect blindly on every system wake.
func TestTriggerReconnectNoOpWhenNotConnected(t *testing.T) {
	c := NewConnection(nil, nil)
	// State is Disconnected — TriggerReconnect must be a no-op.
	c.TriggerReconnect()
	select {
	case <-c.wakeCh:
		t.Error("wakeCh received a signal while disconnected")
	default:
	}
}
