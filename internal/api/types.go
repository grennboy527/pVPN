package api

import "time"

// Auth types

type AuthInfoRequest struct {
	Username string `json:"Username"`
	Intent   string `json:"Intent"`
}

type AuthInfoResponse struct {
	Code            int    `json:"Code"`
	Version         int    `json:"Version"`
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
	TwoFA           struct {
		Enabled int `json:"Enabled"`
		TOTP    int `json:"TOTP"`
	} `json:"2FA"`
}

type AuthRequest struct {
	Username        string `json:"Username"`
	ClientEphemeral string `json:"ClientEphemeral"`
	ClientProof     string `json:"ClientProof"`
	SRPSession      string `json:"SRPSession"`
}

type AuthResponse struct {
	Code         int      `json:"Code"`
	AccessToken  string   `json:"AccessToken"`
	RefreshToken string   `json:"RefreshToken"`
	TokenType    string   `json:"TokenType"`
	UID          string   `json:"UID"`
	UserID       string   `json:"UserID"`
	ServerProof  string   `json:"ServerProof"`
	Scope        string   `json:"Scope"`
	Scopes       []string `json:"Scopes"`
	ExpiresIn    int      `json:"ExpiresIn"`
	TwoFA        struct {
		Enabled int `json:"Enabled"`
		TOTP    int `json:"TOTP"`
	} `json:"2FA"`
}

type Auth2FARequest struct {
	TwoFactorCode string `json:"TwoFactorCode"`
}

type Auth2FAResponse struct {
	Code   int      `json:"Code"`
	Scopes []string `json:"Scopes"`
	Scope  string   `json:"Scope"`
}

type RefreshRequest struct {
	ResponseType string `json:"ResponseType"`
	GrantType    string `json:"GrantType"`
	RefreshToken string `json:"RefreshToken"`
	RedirectURI  string `json:"RedirectURI"`
}

type RefreshResponse struct {
	Code         int    `json:"Code"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	ExpiresIn    int    `json:"ExpiresIn"`
	Scope        string `json:"Scope"`
	UID          string `json:"UID"`
}

// API error response

type APIError struct {
	Code    int         `json:"Code"`
	Error   string      `json:"Error"`
	Details interface{} `json:"Details,omitempty"`
}

func (e *APIError) IsSuccess() bool {
	return e.Code == 1000 || e.Code == 1001
}

// VPN types

type VPNInfoResponse struct {
	Code int     `json:"Code"`
	VPN  VPNInfo `json:"VPN"`
}

type VPNInfo struct {
	ExpirationTime int      `json:"ExpirationTime"`
	Name           string   `json:"Name"`
	Password       string   `json:"Password"`
	GroupID        string   `json:"GroupID"`
	Status         int      `json:"Status"`
	PlanName       string   `json:"PlanName"`
	PlanTitle      string   `json:"PlanTitle"`
	MaxTier        int      `json:"MaxTier"`
	MaxConnect     int      `json:"MaxConnect"`
	Groups         []string `json:"Groups"`
}

// Server list types

type LogicalsResponse struct {
	Code             int             `json:"Code"`
	LogicalServers   []LogicalServer `json:"LogicalServers"`
	LastModifiedTime string          `json:"LastModifiedTime,omitempty"`
}

type LogicalServer struct {
	ID           string           `json:"ID"`
	Name         string           `json:"Name"`
	EntryCountry string           `json:"EntryCountry"`
	ExitCountry  string           `json:"ExitCountry"`
	Domain       string           `json:"Domain"`
	Tier         int              `json:"Tier"`
	Features     int              `json:"Features"`
	Region       string           `json:"Region,omitempty"`
	City         string           `json:"City,omitempty"`
	Score        float64          `json:"Score"`
	Load         int              `json:"Load"`
	Status       int              `json:"Status"`
	HostCountry  string           `json:"HostCountry,omitempty"`
	Location     ServerLocation   `json:"Location"`
	Servers      []PhysicalServer `json:"Servers"`
}

type PhysicalServer struct {
	ID                 string `json:"ID"`
	EntryIP            string `json:"EntryIP"`
	ExitIP             string `json:"ExitIP"`
	Domain             string `json:"Domain"`
	Status             int    `json:"Status"`
	Generation         int    `json:"Generation"`
	Label              string `json:"Label"`
	X25519PublicKey    string `json:"X25519PublicKey"`
	ServicesDownReason string `json:"ServicesDownReason,omitempty"`
}

type ServerLocation struct {
	Lat  float64 `json:"Lat"`
	Long float64 `json:"Long"`
}

// Server feature bitmask
const (
	ServerFeatureSecureCore = 1
	ServerFeatureTor        = 2
	ServerFeatureP2P        = 4
	ServerFeatureStreaming  = 8
	ServerFeatureIPv6       = 16
)

// Server tiers
const (
	ServerTierFree      = 0
	ServerTierBasic     = 1 // Legacy, treat as Plus
	ServerTierPlus      = 2
	ServerTierVisionary = 3
)

func (s *LogicalServer) HasFeature(feature int) bool {
	return s.Features&feature != 0
}

func (s *LogicalServer) IsOnline() bool {
	return s.Status == 1
}

func (s *LogicalServer) IsSecureCore() bool {
	return s.HasFeature(ServerFeatureSecureCore)
}

func (s *LogicalServer) IsP2P() bool {
	return s.HasFeature(ServerFeatureP2P)
}

func (s *LogicalServer) IsTor() bool {
	return s.HasFeature(ServerFeatureTor)
}

func (s *LogicalServer) IsStreaming() bool {
	return s.HasFeature(ServerFeatureStreaming)
}

// EffectiveTier returns the tier, treating legacy Basic as Plus.
func (s *LogicalServer) EffectiveTier() int {
	if s.Tier == ServerTierBasic {
		return ServerTierPlus
	}
	return s.Tier
}

// BestServer returns the first online physical server, or nil.
func (s *LogicalServer) BestServer() *PhysicalServer {
	for i := range s.Servers {
		if s.Servers[i].Status == 1 {
			return &s.Servers[i]
		}
	}
	return nil
}

// Certificate types

type CertificateRequest struct {
	ClientPublicKey     string              `json:"ClientPublicKey"`
	ClientPublicKeyMode string              `json:"ClientPublicKeyMode"`
	Mode                string              `json:"Mode"`
	DeviceName          string              `json:"DeviceName"`
	Duration            string              `json:"Duration"`
	Features            CertificateFeatures `json:"Features"`
}

type CertificateFeatures struct {
	NetShieldLevel int  `json:"NetShieldLevel"`
	RandomNAT      bool `json:"RandomNAT"`
	SplitTCP       bool `json:"SplitTCP"`
	PortForwarding bool `json:"PortForwarding"`
}

type CertificateResponse struct {
	Code                 int    `json:"Code"`
	SerialNumber         string `json:"SerialNumber"`
	ClientKeyFingerprint string `json:"ClientKeyFingerprint"`
	ClientKey            string `json:"ClientKey"`
	Certificate          string `json:"Certificate"`
	ExpirationTime       int64  `json:"ExpirationTime"`
	RefreshTime          int64  `json:"RefreshTime"`
	Mode                 string `json:"Mode"`
	DeviceName           string `json:"DeviceName"`
	ServerPublicKeyMode  string `json:"ServerPublicKeyMode"`
	ServerPublicKey      string `json:"ServerPublicKey"`
}

func (c *CertificateResponse) ExpiresAt() time.Time {
	return time.Unix(c.ExpirationTime, 0)
}

func (c *CertificateResponse) RefreshAt() time.Time {
	return time.Unix(c.RefreshTime, 0)
}

// Client config types

type ClientConfigResponse struct {
	Code          int           `json:"Code"`
	DefaultPorts  DefaultPorts  `json:"DefaultPorts"`
	HolesIPs      []string      `json:"HolesIPs"`
	FeatureFlags  FeatureFlags  `json:"FeatureFlags"`
	SmartProtocol SmartProtocol `json:"SmartProtocol"`
}

type DefaultPorts struct {
	OpenVPN   ProtocolPorts `json:"OpenVPN"`
	WireGuard ProtocolPorts `json:"WireGuard"`
}

type ProtocolPorts struct {
	UDP []int `json:"UDP"`
	TCP []int `json:"TCP"`
}

type FeatureFlags struct {
	NetShield      bool `json:"NetShield"`
	PortForwarding bool `json:"PortForwarding"`
	ModerateNAT    bool `json:"ModerateNAT"`
	VpnAccelerator bool `json:"VpnAccelerator"`
	WireGuardTls   bool `json:"WireGuardTls"`
}

type SmartProtocol struct {
	WireGuard    bool `json:"WireGuard"`
	WireGuardTCP bool `json:"WireGuardTCP"`
	WireGuardTLS bool `json:"WireGuardTLS"`
}

// Location types

type LocationResponse struct {
	Code    int     `json:"Code"`
	IP      string  `json:"IP"`
	Lat     float64 `json:"Lat"`
	Long    float64 `json:"Long"`
	Country string  `json:"Country"`
	ISP     string  `json:"ISP"`
}

// Session types (for persistence)

type Session struct {
	UID          string `json:"uid"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	// Ed25519 private key in base64 for certificate re-requests
	PrivateKey string `json:"private_key,omitempty"`
	// Login email/username used for display purposes
	LoginEmail string `json:"login_email,omitempty"`
}

// Sessions list

type SessionsResponse struct {
	Code     int          `json:"Code"`
	Sessions []VPNSession `json:"Sessions"`
}

type VPNSession struct {
	SessionID string `json:"SessionID"`
	ExitIP    string `json:"ExitIP"`
	Protocol  string `json:"Protocol"`
}
