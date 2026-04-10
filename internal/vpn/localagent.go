package vpn

import (
	"fmt"
	"sync"
	"time"

	"github.com/ProtonVPN/go-vpn-lib/localAgent"
	"github.com/YourDoritos/pvpn/internal/api"
)

const (
	// LocalAgentHost is the address of the Local Agent on the VPN server.
	LocalAgentHost = "10.2.0.1:65432"

	// ProtonVPNRootCA is the root CA certificate for verifying the Local Agent server.
	ProtonVPNRootCA = `-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJDSDEV
MBMGA1UEChMMUHJvdG9uVlBOIEFHMRowGAYDVQQDExFQcm90b25WUE4gUm9vdCBD
QTAeFw0xNzAyMTUxNDM4MDBaFw0yNzAyMTUxNDM4MDBaMEAxCzAJBgNVBAYTAkNI
MRUwEwYDVQQKEwxQcm90b25WUE4gQUcxGjAYBgNVBAMTEVByb3RvblZQTiBSb290
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt+BsSsZg7+AuqTq7
vDbPzfygtl9f8fLJqO4amsyOXlI7pquL5IsEZhpWyJIIvYybqS4s1/T7BbvHPLVE
wlrq8A5DBIXcfuXrBbKoYkmpICGc2u1KYVGOZ9A+PH9z4Tr6OXFfXRnsbZToie8t
2Xjv/dZDdUDAqeW89I/mXg3k5x08m2nfGCQDm4gCanN1r5MT7ge56z0MkY3FFGCO
qRwspIEUzu1ZqGSTkG1eQiOYIrdOF5cc7n2APyvBIcfvp/W3cpTOEmEBJ7/14RnX
nHo0fcx61Inx/6ZxzKkW8BMdGGQF3tF6u2M0FjVN0lLH9S0ul1TgoOS56yEJ34hr
JSRTqHuar3t/xdCbKFZjyXFZFNsXVvgJu34CNLrHHTGJj9jiUfFnxWQYMo9UNUd4
a3PPG1HnbG7LAjlvj5JlJ5aqO5gshdnqb9uIQeR2CdzcCJgklwRGCyDT1pm7eoiv
WV19YBd81vKulLzgPavu3kRRe83yl29It2hwQ9FMs5w6ZV/X6ciTKo3etkX9nBD9
ZzJPsGQsBUy7CzO1jK4W01+u3ItmQS+1s4xtcFxdFY8o/q1zoqBlxpe5MQIWN6Qa
lryiET74gMHE/S5WrPlsq/gehxsdgc6GDUXG4dk8vn6OUMa6wb5wRO3VXGEc67IY
m4mDFTYiPvLaFOxtndlUWuCruKcCAwEAAaOBpzCBpDAMBgNVHRMEBTADAQH/MB0G
A1UdDgQWBBSDkIaYhLVZTwyLNTetNB2qV0gkVDBoBgNVHSMEYTBfgBSDkIaYhLVZ
TwyLNTetNB2qV0gkVKFEpEIwQDELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFByb3Rv
blZQTiBBRzEaMBgGA1UEAxMRUHJvdG9uVlBOIFJvb3QgQ0GCAQEwCwYDVR0PBAQD
AgEGMA0GCSqGSIb3DQEBDQUAA4ICAQCYr7LpvnfZXBCxVIVc2ea1fjxQ6vkTj0zM
htFs3qfeXpMRf+g1NAh4vv1UIwLsczilMt87SjpJ25pZPyS3O+/VlI9ceZMvtGXd
MGfXhTDp//zRoL1cbzSHee9tQlmEm1tKFxB0wfWd/inGRjZxpJCTQh8oc7CTziHZ
ufS+Jkfpc4Rasr31fl7mHhJahF1j/ka/OOWmFbiHBNjzmNWPQInJm+0ygFqij5qs
51OEvubR8yh5Mdq4TNuWhFuTxpqoJ87VKaSOx/Aefca44Etwcj4gHb7LThidw/ky
zysZiWjyrbfX/31RX7QanKiMk2RDtgZaWi/lMfsl5O+6E2lJ1vo4xv9pW8225B5X
eAeXHCfjV/vrrCFqeCprNF6a3Tn/LX6VNy3jbeC+167QagBOaoDA01XPOx7Odhsb
Gd7cJ5VkgyycZgLnT9zrChgwjx59JQosFEG1DsaAgHfpEl/N3YPJh68N7fwN41Cj
zsk39v6iZdfuet/sP7oiP5/gLmA/CIPNhdIYxaojbLjFPkftVjVPn49RqwqzJJPR
N8BOyb94yhQ7KO4F3IcLT/y/dsWitY0ZH4lCnAVV/v2YjWAWS3OWyC8BFx/Jmc3W
DK/yPwECUcPgHIeXiRjHnJt0Zcm23O2Q3RphpU+1SO3XixsXpOVOYP6rJIXW9bMZ
A1gTTlpi7A==
-----END CERTIFICATE-----`
)

// LocalAgent wraps the go-vpn-lib localAgent.AgentConnection.
type LocalAgent struct {
	mu   sync.RWMutex
	conn *localAgent.AgentConnection

	// State tracking
	state   string
	status  *localAgent.StatusMessage
	lastErr error

	// Channels for synchronization
	connectedCh chan struct{} // closed when agent reaches "Connected" state
	errorCh     chan error    // receives terminal errors

	// Callbacks
	onLog func(string)
}

// NewLocalAgent creates a new Local Agent connection.
// It connects to the Local Agent server via mTLS using the VPN certificate.
func NewLocalAgent(kp *api.KeyPair, cert *api.CertificateResponse, serverDomain string, features *localAgent.Features) (*LocalAgent, error) {
	la := &LocalAgent{
		connectedCh: make(chan struct{}),
		errorCh:     make(chan error, 1),
	}

	clientCertPEM := cert.Certificate
	clientKeyPEM := kp.Ed25519.PrivateKeyPKIXPem()

	conn, err := localAgent.NewAgentConnection(
		clientCertPEM,
		clientKeyPEM,
		ProtonVPNRootCA,
		LocalAgentHost,
		serverDomain,
		la, // implements NativeClient
		features,
		true, // connectivity available
		0,    // default keepalive
		0,    // default keepalive max count
	)
	if err != nil {
		return nil, fmt.Errorf("create local agent connection: %w", err)
	}
	la.conn = conn

	return la, nil
}

// WaitConnected blocks until the Local Agent reaches "Connected" state or times out.
func (la *LocalAgent) WaitConnected(timeout time.Duration) error {
	select {
	case <-la.connectedCh:
		return nil
	case err := <-la.errorCh:
		return fmt.Errorf("local agent error: %w", err)
	case <-time.After(timeout):
		la.mu.RLock()
		state := la.state
		la.mu.RUnlock()
		return fmt.Errorf("local agent timeout waiting for Connected (current state: %s)", state)
	}
}

// Close shuts down the Local Agent connection.
func (la *LocalAgent) Close() {
	if la.conn != nil {
		la.conn.Close()
	}
}

// Status returns the last received status message.
func (la *LocalAgent) Status() *localAgent.StatusMessage {
	la.mu.RLock()
	defer la.mu.RUnlock()
	return la.status
}

// SetFeatures updates the requested features on the connection.
func (la *LocalAgent) SetFeatures(features *localAgent.Features) {
	if la.conn != nil {
		la.conn.SetFeatures(features)
	}
}

// NativeClient interface implementation

func (la *LocalAgent) Log(text string) {
	if la.onLog != nil {
		la.onLog(text)
	}
}

func (la *LocalAgent) OnState(state string) {
	la.mu.Lock()
	la.state = state
	la.mu.Unlock()

	consts := localAgent.Constants()
	switch state {
	case consts.StateConnected:
		select {
		case <-la.connectedCh:
			// already closed
		default:
			close(la.connectedCh)
		}
	case consts.StateClientCertificateExpiredError,
		consts.StateClientCertificateUnknownCA,
		consts.StateServerCertificateError:
		select {
		case la.errorCh <- fmt.Errorf("local agent terminal state: %s", state):
		default:
		}
	}
}

func (la *LocalAgent) OnError(code int, description string) {
	la.mu.Lock()
	la.lastErr = fmt.Errorf("local agent error %d: %s", code, description)
	la.mu.Unlock()
}

func (la *LocalAgent) OnStatusUpdate(status *localAgent.StatusMessage) {
	la.mu.Lock()
	la.status = status
	la.mu.Unlock()
}

func (la *LocalAgent) OnTlsSessionStarted() {}
func (la *LocalAgent) OnTlsSessionEnded()   {}

// DefaultFeatures returns the default Local Agent features for a VPN connection.
// For Secure Core servers, the "bouncing" feature is set to the entry country code.
func DefaultFeatures(cfg *api.CertificateFeatures, server *api.LogicalServer) *localAgent.Features {
	f := localAgent.NewFeatures()
	f.SetInt("netshield-level", int64(cfg.NetShieldLevel))
	f.SetBool("split-tcp", cfg.SplitTCP)
	f.SetBool("randomized-nat", cfg.RandomNAT)
	f.SetBool("port-forwarding", cfg.PortForwarding)
	if server != nil && server.IsSecureCore() {
		f.SetString("bouncing", server.EntryCountry)
	} else {
		f.SetString("bouncing", "0")
	}
	f.SetBool("jail", false)
	return f
}
