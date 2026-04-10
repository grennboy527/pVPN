package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

const (
	SocketPath = "/run/pvpn/pvpn.sock"
)

// Request is a command from client to daemon.
type Request struct {
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a reply from daemon to client.
type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Event is a push notification from daemon to client.
type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// --- Command parameter types ---

type LoginParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TwoFA    string `json:"two_fa,omitempty"`
}

type ConnectParams struct {
	Server   string `json:"server"`             // server name, country code, or "fastest"
	Protocol string `json:"protocol,omitempty"` // "smart", "wireguard", "stealth"
}

type SettingsSetParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// --- Response data types ---

type StatusData struct {
	State         string `json:"state"`
	Server        string `json:"server,omitempty"`
	ServerIP      string `json:"server_ip,omitempty"`
	Country       string `json:"country,omitempty"`
	EntryCountry  string `json:"entry_country,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Duration      int64  `json:"duration_sec,omitempty"` // seconds connected
	RxBytes       int64  `json:"rx_bytes,omitempty"`
	TxBytes       int64  `json:"tx_bytes,omitempty"`
	Handshake     int64  `json:"handshake_epoch,omitempty"`
	ForwardedPort uint16 `json:"forwarded_port,omitempty"`
	Username      string `json:"username,omitempty"`
	PlanName      string `json:"plan_name,omitempty"`
}

type ServerEntry struct {
	Name     string `json:"name"`
	Country  string `json:"country"`
	City     string `json:"city,omitempty"`
	Load     int    `json:"load"`
	Tier     int    `json:"tier"`
	Features int    `json:"features"`
	Online   bool   `json:"online"`
}

type ServersData struct {
	Servers []ServerEntry `json:"servers"`
}

// --- Event data types ---

type StateChangedData struct {
	State        string `json:"state"`
	Server       string `json:"server,omitempty"`
	Country      string `json:"country,omitempty"`
	EntryCountry string `json:"entry_country,omitempty"`
	Error        string `json:"error,omitempty"`
}

type StatsUpdateData struct {
	RxBytes   int64 `json:"rx_bytes"`
	TxBytes   int64 `json:"tx_bytes"`
	Handshake int64 `json:"handshake_epoch"`
}

type LogData struct {
	Message string `json:"message"`
}

// --- Wire protocol helpers ---
// Each message is a single JSON line terminated by \n.

// WriteJSON writes a JSON-encoded message followed by newline.
func WriteJSON(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// ReadJSON reads a newline-delimited JSON message.
func ReadJSON(r *bufio.Reader, v interface{}) error {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// Conn wraps a net.Conn with buffered reading and JSON helpers.
type Conn struct {
	Raw    net.Conn
	Reader *bufio.Reader
}

func NewConn(c net.Conn) *Conn {
	return &Conn{Raw: c, Reader: bufio.NewReader(c)}
}

func (c *Conn) SendRequest(req *Request) error {
	return WriteJSON(c.Raw, req)
}

func (c *Conn) ReadResponse() (*Response, error) {
	var resp Response
	if err := ReadJSON(c.Reader, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Conn) SendResponse(resp *Response) error {
	return WriteJSON(c.Raw, resp)
}

func (c *Conn) SendEvent(evt *Event) error {
	return WriteJSON(c.Raw, evt)
}

func (c *Conn) Close() error {
	return c.Raw.Close()
}

// MarshalData is a helper to marshal a struct into json.RawMessage.
func MarshalData(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
