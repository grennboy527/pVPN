package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalData(t *testing.T) {
	data := MarshalData(StatusData{State: "Connected", Server: "CH#1"})
	var sd StatusData
	if err := json.Unmarshal(data, &sd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sd.State != "Connected" || sd.Server != "CH#1" {
		t.Errorf("got %+v", sd)
	}
}

func TestRequestJSON(t *testing.T) {
	req := Request{Command: "connect", Params: MarshalData(ConnectParams{Server: "CH#1"})}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command != "connect" {
		t.Errorf("expected connect, got %s", decoded.Command)
	}
	var params ConnectParams
	json.Unmarshal(decoded.Params, &params)
	if params.Server != "CH#1" {
		t.Errorf("expected CH#1, got %s", params.Server)
	}
}

func TestResponseJSON(t *testing.T) {
	resp := Response{OK: true, Data: MarshalData(StatusData{State: "disconnected"})}
	data, _ := json.Marshal(resp)
	var decoded Response
	json.Unmarshal(data, &decoded)
	if !decoded.OK {
		t.Error("expected OK=true")
	}
}

func TestResponseError(t *testing.T) {
	resp := Response{OK: false, Error: "not found"}
	data, _ := json.Marshal(resp)
	var decoded Response
	json.Unmarshal(data, &decoded)
	if decoded.OK || decoded.Error != "not found" {
		t.Errorf("got %+v", decoded)
	}
}

func TestEventJSON(t *testing.T) {
	evt := Event{Type: "state-changed", Data: MarshalData(StateChangedData{
		State: "Connected", Server: "DE#1", Country: "DE",
	})}
	data, _ := json.Marshal(evt)
	var decoded Event
	json.Unmarshal(data, &decoded)
	if decoded.Type != "state-changed" {
		t.Errorf("got type %s", decoded.Type)
	}
	var sd StateChangedData
	json.Unmarshal(decoded.Data, &sd)
	if sd.State != "Connected" || sd.Server != "DE#1" {
		t.Errorf("got %+v", sd)
	}
}

func TestWriteReadJSON(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Command: "status"}
	if err := WriteJSON(&buf, &req); err != nil {
		t.Fatal(err)
	}
	// Should end with newline
	if buf.Bytes()[buf.Len()-1] != '\n' {
		t.Error("expected trailing newline")
	}

	reader := bufio.NewReader(&buf)
	var decoded Request
	if err := ReadJSON(reader, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command != "status" {
		t.Errorf("expected status, got %s", decoded.Command)
	}
}

func TestStatusDataRoundTrip(t *testing.T) {
	original := StatusData{
		State: "Connected", Server: "US#1", ServerIP: "1.2.3.4",
		Country: "US", Protocol: "wireguard", Duration: 120,
		RxBytes: 1000, TxBytes: 2000, ForwardedPort: 54321,
		Username: "user@example.com", PlanName: "Plus",
	}
	data := MarshalData(original)
	var decoded StatusData
	json.Unmarshal(data, &decoded)
	if decoded != original {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", decoded, original)
	}
}

func TestStatsUpdateDataRoundTrip(t *testing.T) {
	original := StatsUpdateData{RxBytes: 12345, TxBytes: 67890, Handshake: 1700000000}
	data := MarshalData(original)
	var decoded StatsUpdateData
	json.Unmarshal(data, &decoded)
	if decoded != original {
		t.Errorf("mismatch: got %+v", decoded)
	}
}

// --- Wire-format golden tests ---
//
// The TUI and CLI talk to the daemon over a Unix socket using these JSON
// shapes. Renaming a field (`rx_bytes` → `rxBytes`, etc.) is a silent
// wire-break between the daemon and older clients — users who `yay -Syu`
// the daemon but haven't restarted their TUI would get cryptic "empty
// value" bugs. These golden tests lock field names byte-for-byte. If one
// of them fails, you're about to ship an incompatible wire change —
// either bump the IPC version or keep the old field name.

func assertJSONEquals(t *testing.T, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Errorf("wire format mismatch:\n got %s\nwant %s", string(got), want)
	}
}

func TestGolden_Request_Connect(t *testing.T) {
	req := Request{
		Command: "connect",
		Params:  MarshalData(ConnectParams{Server: "CH#1", Protocol: "wireguard"}),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEquals(t, data,
		`{"command":"connect","params":{"server":"CH#1","protocol":"wireguard"}}`)
}

func TestGolden_Request_ConnectOmitProtocol(t *testing.T) {
	// Protocol is omitempty — unset should not appear on the wire.
	req := Request{
		Command: "connect",
		Params:  MarshalData(ConnectParams{Server: "fastest"}),
	}
	data, _ := json.Marshal(req)
	assertJSONEquals(t, data,
		`{"command":"connect","params":{"server":"fastest"}}`)
}

func TestGolden_Request_Login(t *testing.T) {
	req := Request{
		Command: "login",
		Params: MarshalData(LoginParams{
			Username: "user@proton.me",
			Password: "secret",
			TwoFA:    "123456",
		}),
	}
	data, _ := json.Marshal(req)
	assertJSONEquals(t, data,
		`{"command":"login","params":{"username":"user@proton.me","password":"secret","two_fa":"123456"}}`)
}

func TestGolden_Request_SettingsSet(t *testing.T) {
	req := Request{
		Command: "settings_set",
		Params:  MarshalData(SettingsSetParams{Key: "killswitch", Value: "true"}),
	}
	data, _ := json.Marshal(req)
	assertJSONEquals(t, data,
		`{"command":"settings_set","params":{"key":"killswitch","value":"true"}}`)
}

func TestGolden_Request_BareStatus(t *testing.T) {
	// No params — the params field must be omitted on the wire.
	req := Request{Command: "status"}
	data, _ := json.Marshal(req)
	assertJSONEquals(t, data, `{"command":"status"}`)
}

func TestGolden_Response_OKEmpty(t *testing.T) {
	resp := Response{OK: true}
	data, _ := json.Marshal(resp)
	assertJSONEquals(t, data, `{"ok":true}`)
}

func TestGolden_Response_Error(t *testing.T) {
	resp := Response{OK: false, Error: "not authenticated"}
	data, _ := json.Marshal(resp)
	assertJSONEquals(t, data, `{"ok":false,"error":"not authenticated"}`)
}

func TestGolden_Response_StatusData(t *testing.T) {
	resp := Response{
		OK: true,
		Data: MarshalData(StatusData{
			State:         "Connected",
			Server:        "CH#10",
			ServerIP:      "1.2.3.4",
			Country:       "CH",
			EntryCountry:  "SE", // secure core
			Protocol:      "wireguard",
			Duration:      3600,
			RxBytes:       1048576,
			TxBytes:       2048,
			Handshake:     1700000000,
			ForwardedPort: 54321,
			Username:      "u@proton.me",
			PlanName:      "Plus",
		}),
	}
	data, _ := json.Marshal(resp)
	// Field order follows struct declaration order — go's encoding/json
	// is deterministic on this, so the golden is stable.
	assertJSONEquals(t, data,
		`{"ok":true,"data":{"state":"Connected","server":"CH#10","server_ip":"1.2.3.4","country":"CH","entry_country":"SE","protocol":"wireguard","duration_sec":3600,"rx_bytes":1048576,"tx_bytes":2048,"handshake_epoch":1700000000,"forwarded_port":54321,"username":"u@proton.me","plan_name":"Plus"}}`)
}

func TestGolden_Response_StatusDataDisconnected(t *testing.T) {
	// Disconnected state — all the optional fields must be omitted.
	resp := Response{
		OK:   true,
		Data: MarshalData(StatusData{State: "Disconnected"}),
	}
	data, _ := json.Marshal(resp)
	assertJSONEquals(t, data,
		`{"ok":true,"data":{"state":"Disconnected"}}`)
}

func TestGolden_Event_StateChanged(t *testing.T) {
	evt := Event{
		Type: "state_changed",
		Data: MarshalData(StateChangedData{
			State:   "Connected",
			Server:  "DE#1",
			Country: "DE",
		}),
	}
	data, _ := json.Marshal(evt)
	assertJSONEquals(t, data,
		`{"type":"state_changed","data":{"state":"Connected","server":"DE#1","country":"DE"}}`)
}

func TestGolden_Event_StateChangedError(t *testing.T) {
	evt := Event{
		Type: "state_changed",
		Data: MarshalData(StateChangedData{
			State: "Error",
			Error: "tls handshake failed",
		}),
	}
	data, _ := json.Marshal(evt)
	assertJSONEquals(t, data,
		`{"type":"state_changed","data":{"state":"Error","error":"tls handshake failed"}}`)
}

func TestGolden_Event_StatsUpdate(t *testing.T) {
	// StatsUpdateData fields are NOT omitempty — the dashboard needs to
	// see explicit zeros to reset counters.
	evt := Event{
		Type: "stats_update",
		Data: MarshalData(StatsUpdateData{RxBytes: 0, TxBytes: 0, Handshake: 0}),
	}
	data, _ := json.Marshal(evt)
	assertJSONEquals(t, data,
		`{"type":"stats_update","data":{"rx_bytes":0,"tx_bytes":0,"handshake_epoch":0}}`)
}

func TestGolden_Event_Log(t *testing.T) {
	evt := Event{
		Type: "log",
		Data: MarshalData(LogData{Message: "reconnecting..."}),
	}
	data, _ := json.Marshal(evt)
	assertJSONEquals(t, data,
		`{"type":"log","data":{"message":"reconnecting..."}}`)
}

// TestWireFormat_LineDelimited verifies the "one JSON object per line"
// framing the daemon and client rely on. If WriteJSON ever stopped
// appending the newline (or added extras), clients would hang on
// ReadBytes('\n') or desync their reader.
func TestWireFormat_LineDelimited(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, &Request{Command: "status"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&buf, &Request{Command: "disconnect"}); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	want := "{\"command\":\"status\"}\n{\"command\":\"disconnect\"}\n"
	if got != want {
		t.Errorf("framing mismatch:\n got %q\nwant %q", got, want)
	}

	// And verify we can read both back as separate messages.
	reader := bufio.NewReader(&buf)
	var r1, r2 Request
	if err := ReadJSON(reader, &r1); err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if err := ReadJSON(reader, &r2); err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if r1.Command != "status" || r2.Command != "disconnect" {
		t.Errorf("got %q, %q", r1.Command, r2.Command)
	}
}
