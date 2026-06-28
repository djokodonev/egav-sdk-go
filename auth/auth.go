// Package auth provides bearer-token acquisition for consuming the EGAV
// platform: a TokenSource interface plus a credentials-based manager that logs
// in against AuthN and keeps the access token fresh.
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenResponse mirrors AuthN's TokenResponse schema.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	UserGUID         string `json:"user_guid"`
	OrgGUID          string `json:"org_guid"`
	Email            string `json:"email"`
	Role             string `json:"role,omitempty"`
	OrgName          string `json:"org_name,omitempty"`
}

// TokenSource yields a valid bearer access token, refreshing as needed.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticTokenSource returns a fixed, pre-obtained access token. Useful when the
// caller already holds a token (e.g. forwarded from a request).
type StaticTokenSource struct{ AccessToken string }

// Token implements TokenSource.
func (s StaticTokenSource) Token(context.Context) (string, error) {
	if s.AccessToken == "" {
		return "", fmt.Errorf("auth: empty static token")
	}
	return s.AccessToken, nil
}

// CredentialsConfig configures password-based login against AuthN.
type CredentialsConfig struct {
	// BaseURL of the AuthN service, e.g. https://authn-api.local.synaptagrid.io:5209
	BaseURL  string
	Email    string
	Password string

	// HTTPClient is used for token calls. Provide one with InsecureSkipVerify
	// set for local self-signed certs. Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// LoginPath / RefreshPath default to the documented portal endpoints; override
	// if your AuthN deployment exposes a different path. Confirm against AuthN's
	// /openapi.json for your deployment.
	LoginPath   string
	RefreshPath string

	// ExpirySkew is how long before expiry we proactively refresh. Default 30s.
	ExpirySkew time.Duration
}

// CredentialsTokenManager logs in with email/password and keeps the access token
// fresh, preferring refresh-token rotation and falling back to a fresh login.
// It is safe for concurrent use.
type CredentialsTokenManager struct {
	cfg CredentialsConfig
	mu  sync.Mutex
	cur *TokenResponse
	exp time.Time
}

// NewCredentialsManager validates config and returns a ready manager.
func NewCredentialsManager(cfg CredentialsConfig) (*CredentialsTokenManager, error) {
	if cfg.BaseURL == "" || cfg.Email == "" || cfg.Password == "" {
		return nil, fmt.Errorf("auth: BaseURL, Email and Password are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/v1/authn/public/login/credentials"
	}
	if cfg.RefreshPath == "" {
		cfg.RefreshPath = "/v1/authn/public/token/refresh"
	}
	if cfg.ExpirySkew == 0 {
		cfg.ExpirySkew = 30 * time.Second
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &CredentialsTokenManager{cfg: cfg}, nil
}

// Token returns a valid access token, refreshing or logging in as needed.
func (m *CredentialsTokenManager) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cur != nil && time.Now().Before(m.exp.Add(-m.cfg.ExpirySkew)) {
		return m.cur.AccessToken, nil
	}

	// Prefer refresh-token rotation when we have one.
	if m.cur != nil && m.cur.RefreshToken != "" {
		if tr, err := m.post(ctx, m.cfg.RefreshPath, map[string]string{"refresh_token": m.cur.RefreshToken}); err == nil {
			m.set(tr)
			return tr.AccessToken, nil
		}
		// Refresh failed (expired/revoked) — fall through to a fresh login.
	}

	tr, err := m.post(ctx, m.cfg.LoginPath, map[string]string{"email": m.cfg.Email, "password": m.cfg.Password})
	if err != nil {
		return "", err
	}
	m.set(tr)
	return tr.AccessToken, nil
}

// Current returns a copy of the most recently obtained token response, if any.
func (m *CredentialsTokenManager) Current() (TokenResponse, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return TokenResponse{}, false
	}
	return *m.cur, true
}

func (m *CredentialsTokenManager) set(tr *TokenResponse) {
	m.cur = tr
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 900 // conservative default if the server omits expires_in
	}
	m.exp = time.Now().Add(time.Duration(ttl) * time.Second)
}

func (m *CredentialsTokenManager) post(ctx context.Context, path string, body any) (*TokenResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		// Never echo credentials; surface only status + sanitized server message.
		return nil, fmt.Errorf("auth: token call failed: http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	// AuthN may return TokenResponse raw OR wrapped in BaseResponse{data:...}.
	var raw TokenResponse
	if err := json.Unmarshal(data, &raw); err == nil && raw.AccessToken != "" {
		return &raw, nil
	}
	var env struct {
		Data TokenResponse `json:"data"`
	}
	if err := json.Unmarshal(data, &env); err == nil && env.Data.AccessToken != "" {
		return &env.Data, nil
	}
	return nil, fmt.Errorf("auth: no access_token in token response")
}
