package egavsdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/djokodonev/egav-sdk-go/auth"
	"github.com/djokodonev/egav-sdk-go/envelope"
)

type org struct {
	GUID string `json:"guid"`
	Name string `json:"name"`
}

func newClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(Config{
		ServiceURLs: map[string]string{"control-plane": url},
		TokenSource: auth.StaticTokenSource{AccessToken: "tok"},
		DefaultHeaders: map[string]string{"X-App-Instance-Guid": "inst-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetDecodesAndSendsAuth(t *testing.T) {
	var gotAuth, gotInst string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotInst = r.Header.Get("X-App-Instance-Guid")
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"guid":"g-1","name":"Acme"}}`))
	}))
	defer srv.Close()

	c := newClient(t, srv.URL)
	out, err := Get[org](context.Background(), c, "control-plane", "/v1/control-plane/portal/org")
	if err != nil {
		t.Fatal(err)
	}
	if out.Data == nil || out.Data.Name != "Acme" {
		t.Fatalf("unexpected data: %+v", out)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotInst != "inst-1" {
		t.Fatalf("instance header = %q", gotInst)
	}
}

func TestGet404IsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"success":false,"status":"error","error_code":404,"message":"Not found"}`))
	}))
	defer srv.Close()

	c := newClient(t, srv.URL)
	_, err := Get[org](context.Background(), c, "control-plane", "/missing")
	var apiErr *envelope.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
		t.Fatalf("expected 404 APIError, got %v", err)
	}
}

func TestRetryOn503ThenSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"guid":"g","name":"ok"}}`))
	}))
	defer srv.Close()

	c := newClient(t, srv.URL)
	out, err := Get[org](context.Background(), c, "control-plane", "/flaky")
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if out.Data.Name != "ok" {
		t.Fatalf("unexpected: %+v", out)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 calls (1 fail + 1 retry), got %d", calls)
	}
}

func TestUnknownApp(t *testing.T) {
	c := newClient(t, "http://example.invalid")
	_, err := Get[org](context.Background(), c, "nope", "/x")
	if err == nil {
		t.Fatal("expected unknown-app error")
	}
}
