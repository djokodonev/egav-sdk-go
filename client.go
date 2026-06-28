// Package egavsdk is a consumer SDK for calling the EGAV / SynaptaGrid platform
// over HTTP: an authenticated, retrying JSON client plus typed helpers that
// decode the platform's BaseResponse envelope.
//
// It is a *consumer* SDK (Tier 1–2): auth + typed REST access + wire envelopes.
// It deliberately does not include the app-building runtime (factory, tenant
// middleware, outbox, scoped CRUD) — that lives in the Python/TS app SDKs.
package egavsdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getek/egav-sdk-go/auth"
	"github.com/getek/egav-sdk-go/envelope"
)

// Config configures a Client.
type Config struct {
	// ServiceURLs maps an app code (e.g. "control-plane", "authz") to its base
	// URL. This is the client-side equivalent of CP's resolve_service: one map,
	// one source of truth, no hardcoded URLs scattered through call sites.
	ServiceURLs map[string]string

	// TokenSource supplies the bearer token for authed calls. May be nil for
	// public-only usage.
	TokenSource auth.TokenSource

	// DefaultHeaders are sent on every request (e.g. X-App-Instance-Guid for
	// instance-scoped reads, X-App-Code).
	DefaultHeaders map[string]string

	// HTTPClient overrides the default client entirely. When nil, one is built
	// from Timeout + InsecureSkipVerify.
	HTTPClient *http.Client

	// InsecureSkipVerify disables TLS verification — required for local dev
	// self-signed certs (mirrors CONTROL_PLANE_VERIFY_SSL=false). Never in prod.
	InsecureSkipVerify bool

	// Timeout for each request. Default 30s.
	Timeout time.Duration

	// MaxRetries on transient failures (connection error / timeout / 5xx).
	// Default 2 (3 attempts total). 4xx are never retried.
	MaxRetries int
}

// Client is a configured platform consumer.
type Client struct {
	serviceURLs map[string]string
	ts          auth.TokenSource
	headers     map[string]string
	hc          *http.Client
	maxRetries  int
}

// New validates config and returns a Client.
func New(cfg Config) (*Client, error) {
	if len(cfg.ServiceURLs) == 0 {
		return nil, errors.New("egavsdk: ServiceURLs is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		tr := &http.Transport{}
		if cfg.InsecureSkipVerify {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — local dev self-signed certs only
		}
		hc = &http.Client{Timeout: timeout, Transport: tr}
	}
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 2
	}
	urls := make(map[string]string, len(cfg.ServiceURLs))
	for k, v := range cfg.ServiceURLs {
		urls[k] = strings.TrimRight(v, "/")
	}
	return &Client{
		serviceURLs: urls,
		ts:          cfg.TokenSource,
		headers:     cfg.DefaultHeaders,
		hc:          hc,
		maxRetries:  maxRetries,
	}, nil
}

func (c *Client) baseURL(app string) (string, error) {
	u, ok := c.serviceURLs[app]
	if !ok {
		return "", fmt.Errorf("egavsdk: unknown app %q (not in ServiceURLs)", app)
	}
	return u, nil
}

// Do issues an authenticated JSON request to the named app and returns the raw
// response for the caller to decode (use Get/Post for typed decoding). It
// retries transient failures with exponential backoff; 4xx are returned
// immediately for the caller to surface as an *envelope.APIError.
func (c *Client) Do(ctx context.Context, app, method, path string, body any) (*http.Response, error) {
	base, err := c.baseURL(app)
	if err != nil {
		return nil, err
	}
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("egavsdk: marshal body: %w", err)
		}
	}
	url := base + path

	var token string
	if c.ts != nil {
		if token, err = c.ts.Token(ctx); err != nil {
			return nil, fmt.Errorf("egavsdk: obtain token: %w", err)
		}
	}

	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return nil, fmt.Errorf("egavsdk: build request: %w", err)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := c.hc.Do(req)
		switch {
		case err != nil:
			lastErr = err // transient (connection/timeout) — retry
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("egavsdk: server status %d", resp.StatusCode)
			if attempt == c.maxRetries {
				return resp, nil // out of retries — let caller Decode into APIError
			}
			resp.Body.Close()
		default:
			return resp, nil
		}

		if attempt < c.maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("egavsdk: request failed after %d attempts: %w", c.maxRetries+1, lastErr)
}

// Get performs a GET and decodes the BaseResponse[T] envelope.
func Get[T any](ctx context.Context, c *Client, app, path string) (*envelope.BaseResponse[T], error) {
	resp, err := c.Do(ctx, app, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	return envelope.Decode[T](resp)
}

// Post performs a POST and decodes the BaseResponse[T] envelope.
func Post[T any](ctx context.Context, c *Client, app, path string, body any) (*envelope.BaseResponse[T], error) {
	resp, err := c.Do(ctx, app, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	return envelope.Decode[T](resp)
}
