package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultBaseURL  = "https://vpn-api.proton.me"
	AppVersion      = "linux-vpn@4.13.1"
	UserAgent       = "ProtonVPN/4.13.1 (Linux; go-pvpn)"
	DefaultTimeout  = 30 * time.Second
	MaxRetries      = 3
)

// Client is the Proton VPN API client. It handles authenticated requests,
// automatic token refresh, and retry logic.
type Client struct {
	httpClient *http.Client
	baseURL    string

	mu           sync.RWMutex
	uid          string
	accessToken  string
	refreshToken string
	loginEmail   string

	// Called when tokens are rotated so the session can be persisted.
	OnTokenRefresh func(uid, accessToken, refreshToken string)
}

// NewClient creates a new API client. If session is non-nil, the client
// is initialized with existing auth tokens.
func NewClient(session *Session) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
	}
	if session != nil {
		c.uid = session.UID
		c.accessToken = session.AccessToken
		c.refreshToken = session.RefreshToken
		c.loginEmail = session.LoginEmail
	}
	return c
}

// SetSession updates the client's auth tokens.
func (c *Client) SetSession(uid, accessToken, refreshToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uid = uid
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// GetSession returns the current session tokens.
func (c *Client) GetSession() Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Session{
		UID:          c.uid,
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
		LoginEmail:   c.loginEmail,
	}
}

// LoginEmail returns the email the user logged in with.
func (c *Client) LoginEmail() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loginEmail
}

// BaseURL returns the API base URL (needed for kill switch pinhole during reconnection).
func (c *Client) BaseURL() string {
	return c.baseURL
}

// IsAuthenticated returns true if the client has auth tokens.
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken != ""
}

// RequestError represents an API error response.
type RequestError struct {
	HTTPStatus int
	Code       int
	Message    string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("API error %d (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
}

// IsAuthError returns true if this error indicates the session is permanently
// dead and the user must re-login (e.g. refresh token revoked, account
// disabled). Transient errors (network, timeout, 5xx) return false.
func (e *RequestError) IsAuthError() bool {
	switch e.Code {
	case 10013: // Refresh token invalid — must re-authenticate
		return true
	case 10002: // Account deleted
		return true
	case 10003: // Account disabled
		return true
	}
	// Any 401 that isn't handled by token refresh is a dead session
	return e.HTTPStatus == 401
}

// IsAuthError checks whether an error represents a permanent auth failure.
// Returns false for network errors, timeouts, and other transient issues.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	if reqErr, ok := err.(*RequestError); ok {
		return reqErr.IsAuthError()
	}
	return false
}

// doRequest executes an HTTP request with auth headers and retry logic.
// It automatically refreshes tokens on 401.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			// Brief pause before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		err := c.doSingleRequest(ctx, method, path, body, result)
		if err == nil {
			return nil
		}

		lastErr = err

		reqErr, ok := err.(*RequestError)
		if !ok {
			continue // Network error, retry
		}

		switch reqErr.HTTPStatus {
		case 401:
			// Try to refresh tokens
			if refreshErr := c.refreshTokens(ctx); refreshErr != nil {
				// Check if the refresh itself got a permanent auth error
				// (e.g. error 10013 = refresh token revoked)
				if IsAuthError(refreshErr) {
					return refreshErr
				}
				return fmt.Errorf("token refresh failed: %w (original: %w)", refreshErr, err)
			}
			continue // Retry with new tokens

		case 429:
			// Rate limited — wait and retry
			continue

		case 503:
			// Service unavailable — retry
			continue

		default:
			// Non-retryable error
			return err
		}
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) doSingleRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-pm-appversion", AppVersion)
	req.Header.Set("User-Agent", UserAgent)

	c.mu.RLock()
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	if c.uid != "" {
		req.Header.Set("x-pm-uid", c.uid)
	}
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Check for API-level error
	if resp.StatusCode >= 400 {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Code != 0 {
			return &RequestError{
				HTTPStatus: resp.StatusCode,
				Code:       apiErr.Code,
				Message:    apiErr.Error,
			}
		}
		return &RequestError{
			HTTPStatus: resp.StatusCode,
			Code:       0,
			Message:    string(respBody),
		}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

// refreshTokens attempts to refresh the access token using the refresh token.
func (c *Client) refreshTokens(ctx context.Context) error {
	c.mu.RLock()
	refreshToken := c.refreshToken
	c.mu.RUnlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	reqBody := RefreshRequest{
		ResponseType: "token",
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
		RedirectURI:  "http://protonmail.ch",
	}

	var result RefreshResponse
	if err := c.doSingleRequest(ctx, http.MethodPost, "/auth/refresh", reqBody, &result); err != nil {
		return err
	}

	c.mu.Lock()
	c.accessToken = result.AccessToken
	c.refreshToken = result.RefreshToken
	c.mu.Unlock()

	if c.OnTokenRefresh != nil {
		c.OnTokenRefresh(c.uid, result.AccessToken, result.RefreshToken)
	}

	return nil
}

// VPN API methods

// GetVPNInfo returns the VPN account info.
func (c *Client) GetVPNInfo(ctx context.Context) (*VPNInfoResponse, error) {
	var result VPNInfoResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v2", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetServers returns the full server list.
func (c *Client) GetServers(ctx context.Context) (*LogicalsResponse, error) {
	var result LogicalsResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v1/logicals?SecureCoreFilter=all", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetClientConfig returns the client configuration.
func (c *Client) GetClientConfig(ctx context.Context) (*ClientConfigResponse, error) {
	var result ClientConfigResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v2/clientconfig", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetLocation returns the client's current IP and location.
func (c *Client) GetLocation(ctx context.Context) (*LocationResponse, error) {
	var result LocationResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v1/location", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSessions returns active VPN sessions.
func (c *Client) GetSessions(ctx context.Context) (*SessionsResponse, error) {
	var result SessionsResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v1/sessions", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RequestCertificate requests a new VPN certificate.
func (c *Client) RequestCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	var result CertificateResponse
	err := c.doRequest(ctx, http.MethodPost, "/vpn/v1/certificate", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetServerLoads fetches just the server loads (lighter than full server list).
func (c *Client) GetServerLoads(ctx context.Context) (*LogicalsResponse, error) {
	var result LogicalsResponse
	err := c.doRequest(ctx, http.MethodGet, "/vpn/v1/loads", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// handleRetryAfter extracts the Retry-After header value.
func handleRetryAfter(resp *http.Response) time.Duration {
	if val := resp.Header.Get("Retry-After"); val != "" {
		if seconds, err := strconv.Atoi(val); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return 5 * time.Second
}
