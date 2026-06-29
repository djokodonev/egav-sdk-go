package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestStaticTokenSource(t *testing.T) {
	if _, err := (StaticTokenSource{}).Token(context.Background()); err == nil {
		t.Fatal("expected error for empty static token")
	}
	tok, err := StaticTokenSource{AccessToken: "abc"}.Token(context.Background())
	if err != nil || tok != "abc" {
		t.Fatalf("got %q, %v", tok, err)
	}
}

// headlessServer is a mock AuthN implementing the 3-step OIDC headless flow.
type headlessServer struct {
	authorizeCalls int32
	mfa            bool
	credStatus     int
}

func (h *headlessServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authn/public/oidc/authorize/headless", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&h.authorizeCalls, 1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["code_challenge"] == "" || body["code_challenge_method"] != "S256" {
			http.Error(w, "missing PKCE", 400)
			return
		}
		_, _ = w.Write([]byte(`{"session_id":"sess-1","tier":"portal"}`))
	})
	mux.HandleFunc("/v1/authn/public/oidc/headless/credentials", func(w http.ResponseWriter, r *http.Request) {
		if h.credStatus != 0 {
			http.Error(w, `{"error_code":401,"message":"Invalid credentials"}`, h.credStatus)
			return
		}
		if h.mfa {
			_, _ = w.Write([]byte(`{"mfa_required":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":"auth-code-1","state":"x"}`))
	})
	mux.HandleFunc("/v1/authn/public/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "auth-code-1" || r.Form.Get("code_verifier") == "" {
			http.Error(w, "bad token request", 400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`))
	})
	return mux
}

func newMgr(t *testing.T, srv *httptest.Server) *OIDCHeadlessTokenManager {
	t.Helper()
	m, err := NewOIDCHeadlessManager(OIDCConfig{
		AuthNBaseURL: srv.URL, ClientID: "cid", RedirectURI: "https://app/callback",
		Email: "x@y.z", Password: "pw", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOIDCHeadlessLoginAndCache(t *testing.T) {
	h := &headlessServer{}
	srv := httptest.NewServer(h.handler())
	defer srv.Close()
	m := newMgr(t, srv)

	tok, err := m.Token(context.Background())
	if err != nil || tok != "tok-1" {
		t.Fatalf("got %q, %v", tok, err)
	}
	// Second call served from cache — no second authorize round-trip.
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&h.authorizeCalls); got != 1 {
		t.Fatalf("expected exactly 1 headless login, got %d", got)
	}
}

func TestOIDCHeadlessMFAUnsupported(t *testing.T) {
	h := &headlessServer{mfa: true}
	srv := httptest.NewServer(h.handler())
	defer srv.Close()
	if _, err := newMgr(t, srv).Token(context.Background()); err == nil {
		t.Fatal("expected MFA-required error")
	}
}

func TestOIDCHeadlessBadCredentials(t *testing.T) {
	h := &headlessServer{credStatus: 401}
	srv := httptest.NewServer(h.handler())
	defer srv.Close()
	if _, err := newMgr(t, srv).Token(context.Background()); err == nil {
		t.Fatal("expected credentials failure")
	}
}

func TestOIDCConfigValidation(t *testing.T) {
	if _, err := NewOIDCHeadlessManager(OIDCConfig{ClientID: "c"}); err == nil {
		t.Fatal("expected validation error for missing fields")
	}
}
