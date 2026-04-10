package stealth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// TLSBind implements conn.Bind for WireGuard-over-TLS (Stealth protocol).
//
// Matches Proton's StdNetBindTcp lazy-connect pattern:
// - Open() just marks the bind as ready, doesn't connect
// - The actual TCP+TLS connection is established on first Send/Receive
// - TunSafe framing wraps WG packets in the TLS stream
type TLSBind struct {
	mu       sync.Mutex
	tcpConn  *net.TCPConn
	tlsConn  *tls.Conn
	endpoint *TLSEndpoint
	closed   bool
	fwmark   uint32

	serverAddr string
	sni        string
	writer     *FrameWriter
	reader     *FrameReader
}

// NewTLSBind creates a new TLS-based WireGuard bind.
func NewTLSBind(serverIP string, port int, sni string) *TLSBind {
	return &TLSBind{
		serverAddr: fmt.Sprintf("%s:%d", serverIP, port),
		sni:        sni,
	}
}

// Open puts the bind into listening state. Connection is established lazily.
func (b *TLSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = false
	return []conn.ReceiveFunc{b.makeReceiveFunc()}, port, nil
}

// getConn returns the active TLS connection, establishing it if needed.
func (b *TLSBind) getConn() (*tls.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, net.ErrClosed
	}

	c, err := b.getConnLocked()
	if err != nil {
		b.closed = true
	}
	return c, err
}

func (b *TLSBind) getConnLocked() (*tls.Conn, error) {
	// Establish TCP if needed
	if b.tcpConn == nil {
		if err := b.dialTCP(); err != nil {
			return nil, err
		}
	}

	// Upgrade to TLS if needed
	if b.tlsConn == nil {
		if err := b.upgradeTLS(); err != nil {
			b.closeLocked()
			return nil, err
		}
	}

	return b.tlsConn, nil
}

func (b *TLSBind) dialTCP() error {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if b.fwmark == 0 {
				return nil
			}
			var setsockoptErr error
			err := c.Control(func(fd uintptr) {
				setsockoptErr = syscall.SetsockoptInt(
					int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(b.fwmark),
				)
			})
			if err != nil {
				return err
			}
			return setsockoptErr
		},
	}

	netConn, err := dialer.DialContext(context.Background(), "tcp", b.serverAddr)
	if err != nil {
		return fmt.Errorf("TCP dial %s: %w", b.serverAddr, err)
	}

	tcp := netConn.(*net.TCPConn)
	tcp.SetLinger(0)
	tcp.SetNoDelay(true)
	tcp.SetKeepAlive(true)
	b.tcpConn = tcp
	return nil
}

func (b *TLSBind) upgradeTLS() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         b.sni,
	}

	tlsConn := tls.Client(b.tcpConn, tlsConf)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	err := tlsConn.Handshake()
	tlsConn.SetDeadline(time.Time{}) // clear deadline

	// Small delay after handshake (matches Proton's implementation)
	time.Sleep(100 * time.Millisecond)

	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("TLS handshake %s: %w", b.serverAddr, err)
	}

	b.tlsConn = tlsConn
	b.writer = NewFrameWriter(tlsConn)
	b.reader = NewFrameReader(tlsConn)

	addr, _ := netip.ParseAddrPort(b.serverAddr)
	b.endpoint = &TLSEndpoint{addr: addr}

	return nil
}

func (b *TLSBind) makeReceiveFunc() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		c, err := b.getConn()
		if err != nil {
			return 0, err
		}
		_ = c // connection is used via b.reader

		n, err := b.reader.ReadPacket(packets[0])
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// Socket error — close so next getConn reconnects
				b.mu.Lock()
				b.closeLocked()
				b.mu.Unlock()
			}
			return 0, err
		}
		sizes[0] = n
		eps[0] = b.endpoint
		return 1, nil
	}
}

// Close tears down the TLS and TCP connections.
func (b *TLSBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true
	return b.closeLocked()
}

func (b *TLSBind) closeLocked() error {
	var err error
	if b.tlsConn != nil {
		err = b.tlsConn.Close()
		b.tlsConn = nil
	}
	if b.tcpConn != nil {
		err = b.tcpConn.Close()
		b.tcpConn = nil
	}
	b.writer = nil
	b.reader = nil
	return err
}

// SetMark stores the fwmark for SO_MARK on the TCP socket.
func (b *TLSBind) SetMark(mark uint32) error {
	b.mu.Lock()
	b.fwmark = mark
	b.mu.Unlock()
	return nil
}

// Send writes WireGuard packets via TunSafe framing over the TLS connection.
func (b *TLSBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	_, err := b.getConn()
	if err != nil {
		return err
	}

	for _, buf := range bufs {
		if err := b.writer.WritePacket(buf); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses a string endpoint.
func (b *TLSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.endpoint = &TLSEndpoint{addr: addr}
	b.mu.Unlock()
	return b.endpoint, nil
}

// BatchSize returns 1 since TCP is a sequential stream.
func (b *TLSBind) BatchSize() int {
	return 1
}

// TLSEndpoint implements conn.Endpoint for the TLS connection.
type TLSEndpoint struct {
	addr netip.AddrPort
}

func (e *TLSEndpoint) ClearSrc()           {}
func (e *TLSEndpoint) SrcToString() string { return "" }
func (e *TLSEndpoint) DstToString() string { return e.addr.String() }
func (e *TLSEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *TLSEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (e *TLSEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}
