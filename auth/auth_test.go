package auth

import (
	"context"
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

func TestCredentialsLoginAndCache(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/authn/public/login/credentials" {
			atomic.AddInt32(&logins, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok-1","refresh_token":"r-1","token_type":"Bearer","expires_in":3600,"user_guid":"u-1","org_guid":"o-1","email":"x@y.z"}`))
			return
		}
		http.Error(w, "nope", 404)
	}))
	defer srv.Close()

	m, err := NewCredentialsManager(CredentialsConfig{
		BaseURL: srv.URL, Email: "x@y.z", Password: "pw", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := m.Token(context.Background())
	if err != nil || tok != "tok-1" {
		t.Fatalf("got %q, %v", tok, err)
	}
	// Second call should be served from cache (no second login).
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&logins); got != 1 {
		t.Fatalf("expected exactly 1 login, got %d", got)
	}
	if cur, ok := m.Current(); !ok || cur.OrgGUID != "o-1" {
		t.Fatalf("Current() = %+v, %v", cur, ok)
	}
}

func TestCredentialsEnvelopedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"access_token":"tok-env","token_type":"Bearer","expires_in":900,"user_guid":"u","org_guid":"o","email":"x@y.z"}}`))
	}))
	defer srv.Close()

	m, _ := NewCredentialsManager(CredentialsConfig{BaseURL: srv.URL, Email: "x@y.z", Password: "pw", HTTPClient: srv.Client()})
	tok, err := m.Token(context.Background())
	if err != nil || tok != "tok-env" {
		t.Fatalf("enveloped login: got %q, %v", tok, err)
	}
}

func TestCredentialsLoginFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"success":false,"status":"error","error_code":401,"message":"Invalid credentials"}`, 401)
	}))
	defer srv.Close()
	m, _ := NewCredentialsManager(CredentialsConfig{BaseURL: srv.URL, Email: "x@y.z", Password: "bad", HTTPClient: srv.Client()})
	if _, err := m.Token(context.Background()); err == nil {
		t.Fatal("expected login failure")
	}
}
