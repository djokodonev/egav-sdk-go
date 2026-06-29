// Package auth provides bearer-token acquisition for consuming the EGAV
// platform: a TokenSource interface, a static token source, and an OIDC
// headless credentials manager that logs in against AuthN and keeps the access
// token fresh.
//
// The platform has no simple ROPC endpoint — portal login is the 3-step OIDC
// headless flow with PKCE:
//
//	1. POST /v1/authn/public/oidc/authorize/headless  -> { session_id }
//	2. POST /v1/authn/public/oidc/headless/credentials -> { code }
//	3. POST /v1/authn/public/oidc/token (form)         -> { access_token, expires_in }
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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

// OIDCConfig configures the headless credentials login against AuthN.
type OIDCConfig struct {
	// AuthNBaseURL, e.g. https://authn-api.local.synaptagrid.io:5209
	AuthNBaseURL string
	// ClientID / RedirectURI of a registered public OIDC client.
	ClientID    string
	RedirectURI string
	// Scope defaults to "openid profile email". Add "offline_access" to receive
	// a refresh token (otherwise the manager simply re-logs in on expiry).
	Scope string

	Email    string
	Password string

	// HTTPClient is used for token calls (provide one with InsecureSkipVerify
	// for local self-signed certs). Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// ExpirySkew is how long before expiry we proactively re-login. Default 30s.
	ExpirySkew time.Duration
}

// OIDCHeadlessTokenManager logs in via the OIDC headless flow and caches the
// access token until shortly before it expires, re-logging in as needed. Safe
// for concurrent use.
type OIDCHeadlessTokenManager struct {
	cfg         OIDCConfig
	mu          sync.Mutex
	accessToken string
	exp         time.Time
}

// NewOIDCHeadlessManager validates config and returns a ready manager.
func NewOIDCHeadlessManager(cfg OIDCConfig) (*OIDCHeadlessTokenManager, error) {
	if cfg.AuthNBaseURL == "" || cfg.ClientID == "" || cfg.RedirectURI == "" || cfg.Email == "" || cfg.Password == "" {
		return nil, fmt.Errorf("auth: AuthNBaseURL, ClientID, RedirectURI, Email and Password are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Scope == "" {
		cfg.Scope = "openid profile email"
	}
	if cfg.ExpirySkew == 0 {
		cfg.ExpirySkew = 30 * time.Second
	}
	cfg.AuthNBaseURL = strings.TrimRight(cfg.AuthNBaseURL, "/")
	return &OIDCHeadlessTokenManager{cfg: cfg}, nil
}

// Token returns a valid access token, logging in via the headless flow if the
// cache is empty or near expiry.
func (m *OIDCHeadlessTokenManager) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accessToken != "" && time.Now().Before(m.exp.Add(-m.cfg.ExpirySkew)) {
		return m.accessToken, nil
	}
	tok, ttl, err := m.login(ctx)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 900
	}
	m.accessToken = tok
	m.exp = time.Now().Add(time.Duration(ttl) * time.Second)
	return tok, nil
}

func (m *OIDCHeadlessTokenManager) login(ctx context.Context) (string, int, error) {
	verifier := randomURLSafe(40)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Step 1 — start a headless authorization session.
	var s1 struct {
		SessionID string `json:"session_id"`
	}
	if err := m.postJSON(ctx, "/v1/authn/public/oidc/authorize/headless", map[string]any{
		"client_id":             m.cfg.ClientID,
		"redirect_uri":          m.cfg.RedirectURI,
		"response_type":         "code",
		"scope":                 m.cfg.Scope,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}, &s1); err != nil {
		return "", 0, fmt.Errorf("authorize/headless: %w", err)
	}
	if s1.SessionID == "" {
		return "", 0, fmt.Errorf("auth: no session_id from authorize/headless")
	}

	// Step 2 — submit credentials, receive an authorization code.
	var s2 struct {
		Code        string `json:"code"`
		MFARequired bool   `json:"mfa_required"`
	}
	if err := m.postJSON(ctx, "/v1/authn/public/oidc/headless/credentials", map[string]any{
		"session_id": s1.SessionID,
		"email":      m.cfg.Email,
		"password":   m.cfg.Password,
	}, &s2); err != nil {
		return "", 0, fmt.Errorf("headless/credentials: %w", err)
	}
	if s2.MFARequired {
		return "", 0, fmt.Errorf("auth: MFA required for this account (not supported by this manager)")
	}
	if s2.Code == "" {
		return "", 0, fmt.Errorf("auth: no authorization code from headless/credentials")
	}

	// Step 3 — exchange the code (with the PKCE verifier) for tokens.
	var s3 struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := m.postForm(ctx, "/v1/authn/public/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {s2.Code},
		"redirect_uri":  {m.cfg.RedirectURI},
		"client_id":     {m.cfg.ClientID},
		"code_verifier": {verifier},
	}, &s3); err != nil {
		return "", 0, fmt.Errorf("token: %w", err)
	}
	if s3.AccessToken == "" {
		return "", 0, fmt.Errorf("auth: no access_token from token endpoint")
	}
	return s3.AccessToken, s3.ExpiresIn, nil
}

func (m *OIDCHeadlessTokenManager) postJSON(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.AuthNBaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return m.do(req, out)
}

func (m *OIDCHeadlessTokenManager) postForm(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.AuthNBaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return m.do(req, out)
}

func (m *OIDCHeadlessTokenManager) do(req *http.Request, out any) error {
	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		// Never echo credentials; surface only status (+ short server text).
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// randomURLSafe returns a base64url (no padding) string from n random bytes —
// used as the PKCE code verifier.
func randomURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
