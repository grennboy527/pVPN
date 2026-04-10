package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

// Client connects to the pvpnd daemon via Unix socket.
type Client struct {
	mu      sync.Mutex
	conn    *Conn
	respCh  chan *Response
	closed  bool
	closeMu sync.Mutex

	// EventHandler is called for push events from the daemon.
	// Called from a background goroutine — must be safe for concurrent use.
	EventHandler func(*Event)
}

// Dial connects to the daemon.
func Dial() (*Client, error) {
	return DialPath(SocketPath)
}

// DialPath connects to the daemon at a custom socket path.
func DialPath(path string) (*Client, error) {
	raw, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w", path, err)
	}
	c := &Client{
		conn:   NewConn(raw),
		respCh: make(chan *Response, 4),
	}
	go c.readLoop()
	return c, nil
}

// readLoop continuously reads from the socket, dispatching events
// and routing responses to the response channel.
func (c *Client) readLoop() {
	for {
		line, err := c.conn.Reader.ReadBytes('\n')
		if err != nil {
			c.closeMu.Lock()
			closed := c.closed
			c.closeMu.Unlock()
			if !closed {
				// Send nil response to unblock any waiting Do()
				select {
				case c.respCh <- nil:
				default:
				}
			}
			return
		}

		// Try as response first
		var resp Response
		if json.Unmarshal(line, &resp) == nil && (resp.OK || resp.Error != "") {
			c.respCh <- &resp
			continue
		}

		// Try as event
		var evt Event
		if json.Unmarshal(line, &evt) == nil && evt.Type != "" {
			if c.EventHandler != nil {
				c.EventHandler(&evt)
			}
			continue
		}

		// Unknown message — treat as response
		if json.Unmarshal(line, &resp) == nil {
			c.respCh <- &resp
		}
	}
}

// Do sends a command and waits for the response.
func (c *Client) Do(command string, params interface{}) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var rawParams json.RawMessage
	if params != nil {
		var err error
		rawParams, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
	}

	req := &Request{Command: command, Params: rawParams}
	if err := c.conn.SendRequest(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	resp := <-c.respCh
	if resp == nil {
		return nil, fmt.Errorf("connection closed")
	}
	return resp, nil
}

func (c *Client) Status() (*StatusData, error) {
	resp, err := c.Do("status", nil)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("status: %s", resp.Error)
	}
	var data StatusData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("unmarshal status: %w", err)
	}
	return &data, nil
}

func (c *Client) Connect(server, protocol string) error {
	resp, err := c.Do("connect", ConnectParams{Server: server, Protocol: protocol})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) Disconnect() error {
	resp, err := c.Do("disconnect", nil)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) Login(username, password, twoFA string) error {
	resp, err := c.Do("login", LoginParams{Username: username, Password: password, TwoFA: twoFA})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) Servers() (*ServersData, error) {
	resp, err := c.Do("servers", nil)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var data ServersData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("unmarshal servers: %w", err)
	}
	return &data, nil
}

// NotifySettingsChanged tells the daemon to reload config and apply any
// settings that can take effect on a live connection (e.g., kill switch).
func (c *Client) NotifySettingsChanged() {
	c.Do("settings", nil)
}

func (c *Client) Logout() error {
	resp, err := c.Do("logout", nil)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func (c *Client) Close() error {
	c.closeMu.Lock()
	c.closed = true
	c.closeMu.Unlock()
	return c.conn.Close()
}
