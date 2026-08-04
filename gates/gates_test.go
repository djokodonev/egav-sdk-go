package gates

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	egavsdk "github.com/djokodonev/egav-sdk-go"
)

// newGates wires a Gates onto an SDK Client pointed at a single test server that
// serves both the control-plane and authz app codes. No network is touched.
func newGates(t *testing.T, url string) *Gates {
	t.Helper()
	c, err := egavsdk.New(egavsdk.Config{
		ServiceURLs: map[string]string{
			"control-plane": url,
			"authz":         url,
		},
		MaxRetries: 0, // deterministic: one attempt per call in tests.
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{Client: c, CPAPIKey: "cp-key", AuthZAPIKey: "authz-key"})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func ptrBool(b bool) *bool { return &b }

// ---- gate 1: auth -----------------------------------------------------------

func TestAuthenticate_200_ReturnsIdentity(t *testing.T) {
	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("x-api-key")
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"user_guid":"u-1","org_guid":"o-1"}}`))
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	id, err := g.Authenticate(context.Background(), "user-bearer-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserGuid != "u-1" || id.OrgGuid != "o-1" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if gotAuth != "Bearer user-bearer-xyz" {
		t.Fatalf("auth header = %q (user bearer must be forwarded)", gotAuth)
	}
	if gotKey != "" {
		t.Fatalf("x-api-key must NOT be sent to portal/me, got %q", gotKey)
	}
}

func TestAuthenticate_401_Unauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"success":false,"status":"error","error_code":401,"message":"bad token"}`))
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	_, err := g.Authenticate(context.Background(), "bad")
	var ue *Unauthenticated
	if !errors.As(err, &ue) || ue.HTTPStatus() != 401 {
		t.Fatalf("expected *Unauthenticated(401), got %v", err)
	}
}

func TestAuthenticate_EmptyBearer_Unauthenticated(t *testing.T) {
	g := newGates(t, "http://example.invalid")
	_, err := g.Authenticate(context.Background(), "   ")
	var ue *Unauthenticated
	if !errors.As(err, &ue) {
		t.Fatalf("expected *Unauthenticated for empty bearer, got %v", err)
	}
}

func TestAuthenticate_503_Unavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	_, err := g.Authenticate(context.Background(), "tok")
	var ua *Unavailable
	if !errors.As(err, &ua) || ua.HTTPStatus() != 503 {
		t.Fatalf("expected *Unavailable(503), got %v", err)
	}
}

// ---- gate 2: permission -----------------------------------------------------

func TestRequirePermission_Allow(t *testing.T) {
	var gotKey, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"allowed":true}}`))
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	err := g.RequirePermission(context.Background(), Identity{UserGuid: "u", OrgGuid: "o"}, "project.create")
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if gotKey != "authz-key" {
		t.Fatalf("x-api-key = %q (app key must be sent to /internal/authorize)", gotKey)
	}
	if gotAuth != "" {
		t.Fatalf("user bearer must NOT be sent to /internal/*, got %q", gotAuth)
	}
	// action must be the substring after the last dot.
	if want := `"action":"create"`; !strings.Contains(gotBody, want) {
		t.Fatalf("body %q missing %q", gotBody, want)
	}
	if want := `"resource_type":"app"`; !strings.Contains(gotBody, want) {
		t.Fatalf("body %q missing default resource_type %q", gotBody, want)
	}
}

func TestRequirePermission_ResourceTypeOverride(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"allowed":true}}`))
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	_ = g.RequirePermission(context.Background(), Identity{UserGuid: "u", OrgGuid: "o"}, "invoice.read", "billing")
	if want := `"resource_type":"billing"`; !strings.Contains(gotBody, want) {
		t.Fatalf("body %q missing %q", gotBody, want)
	}
}

func TestRequirePermission_Deny403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"status":"success","data":{"allowed":false}}`))
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	err := g.RequirePermission(context.Background(), Identity{UserGuid: "u", OrgGuid: "o"}, "project.create")
	var pd *PermissionDenied
	if !errors.As(err, &pd) {
		t.Fatalf("expected *PermissionDenied, got %v", err)
	}
	if pd.HTTPStatus() != 403 || pd.ErrorCode() != 4031 {
		t.Fatalf("expected 403/4031, got %d/%d", pd.HTTPStatus(), pd.ErrorCode())
	}
	if pd.Message != "Permission denied: project.create" {
		t.Fatalf("unexpected message: %q", pd.Message)
	}
}

func TestRequirePermission_AuthZDown503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	g := newGates(t, srv.URL)
	err := g.RequirePermission(context.Background(), Identity{UserGuid: "u", OrgGuid: "o"}, "project.create")
	var ua *Unavailable
	if !errors.As(err, &ua) || ua.HTTPStatus() != 503 {
		t.Fatalf("expected *Unavailable(503) fail-closed, got %v", err)
	}
}

// ---- gates 3-5: entitlements fetch -----------------------------------------

const fullEntitlements = `{"success":true,"status":"success","data":{
  "plan_code":"pro","plan_tier":"pro","subscription_status":"active",
  "features":{
    "projects":{"enabled":true,"config":{}},
    "max_projects":{"enabled":true,"config":{"limit":25}},
    "platform.sso":{"enabled":false,"config":{}},
    "unlimited_things":{"enabled":true,"config":{"limit":-1}},
    "no_quota":{"enabled":true,"config":{}}
  }}}`

func entServer(t *testing.T, body string, status int) (*httptest.Server, *string) {
	t.Helper()
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		if status != 0 && status != 200 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	return srv, &gotKey
}

func TestEntitlements_FetchUsesCPKey(t *testing.T) {
	srv, gotKey := entServer(t, fullEntitlements, 200)
	defer srv.Close()

	g := newGates(t, srv.URL)
	ent, err := g.Entitlements(context.Background(), "o-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *gotKey != "cp-key" {
		t.Fatalf("x-api-key = %q (CP key must be sent), ", *gotKey)
	}
	if ent.SubscriptionStatus != "active" || len(ent.Features) != 5 {
		t.Fatalf("unexpected entitlements: %+v", ent)
	}
}

func TestEntitlements_Empty503(t *testing.T) {
	srv, _ := entServer(t, `{"success":true,"status":"success","data":{}}`, 200)
	defer srv.Close()

	g := newGates(t, srv.URL)
	_, err := g.Entitlements(context.Background(), "o-1")
	var ua *Unavailable
	if !errors.As(err, &ua) || ua.HTTPStatus() != 503 {
		t.Fatalf("expected *Unavailable(503) on empty payload, got %v", err)
	}
}

func TestEntitlements_ServerError503(t *testing.T) {
	srv, _ := entServer(t, "", 500)
	defer srv.Close()

	g := newGates(t, srv.URL)
	_, err := g.Entitlements(context.Background(), "o-1")
	var ua *Unavailable
	if !errors.As(err, &ua) {
		t.Fatalf("expected *Unavailable on 5xx, got %v", err)
	}
}

// ---- gate 3: subscription ---------------------------------------------------

func TestRequireActiveSubscription_Active(t *testing.T) {
	if err := (&Gates{}).RequireActiveSubscription(Entitlements{SubscriptionStatus: "active"}); err != nil {
		t.Fatalf("active should pass, got %v", err)
	}
}

func TestRequireActiveSubscription_Trialing(t *testing.T) {
	if err := (&Gates{}).RequireActiveSubscription(Entitlements{SubscriptionStatus: "trialing"}); err != nil {
		t.Fatalf("trialing should pass, got %v", err)
	}
}

func TestRequireActiveSubscription_Inactive402(t *testing.T) {
	err := (&Gates{}).RequireActiveSubscription(Entitlements{SubscriptionStatus: "past_due"})
	var si *SubscriptionInactive
	if !errors.As(err, &si) || si.HTTPStatus() != 402 {
		t.Fatalf("expected *SubscriptionInactive(402), got %v", err)
	}
	if si.Action == nil || si.Action.URL != "/billing/plans" {
		t.Fatalf("expected renew action, got %+v", si.Action)
	}
}

func TestRequireActiveSubscription_GateBlocked402(t *testing.T) {
	ent := Entitlements{
		SubscriptionStatus: "active", // gate.blocked overrides status.
		Gate:               &Gate{Access: "blocked", Reason: "payment_failed", Message: "Card declined.", Action: &Action{Kind: "update_payment", Label: "Update card", URL: "/billing"}},
	}
	err := (&Gates{}).RequireActiveSubscription(ent)
	var si *SubscriptionInactive
	if !errors.As(err, &si) || si.HTTPStatus() != 402 {
		t.Fatalf("expected *SubscriptionInactive(402) from blocked gate, got %v", err)
	}
	if si.Reason != "payment_failed" || si.Message != "Card declined." {
		t.Fatalf("gate object should drive reason/message, got %+v", si)
	}
}

func TestRequireActiveSubscription_GateOK(t *testing.T) {
	ent := Entitlements{SubscriptionStatus: "active", Gate: &Gate{Access: "ok"}}
	if err := (&Gates{}).RequireActiveSubscription(ent); err != nil {
		t.Fatalf("gate ok + active should pass, got %v", err)
	}
}

// ---- gate 4: feature --------------------------------------------------------

func TestRequireFeature_Enabled(t *testing.T) {
	ent := Entitlements{Features: map[string]FeatureEntry{"projects": {Enabled: ptrBool(true)}}}
	if err := (&Gates{}).RequireFeature(ent, "projects"); err != nil {
		t.Fatalf("enabled feature should pass, got %v", err)
	}
}

func TestRequireFeature_Disabled403(t *testing.T) {
	ent := Entitlements{Features: map[string]FeatureEntry{"platform.sso": {Enabled: ptrBool(false)}}}
	err := (&Gates{}).RequireFeature(ent, "platform.sso")
	var fd *FeatureDisabled
	if !errors.As(err, &fd) || fd.HTTPStatus() != 403 || fd.Kind() != "feature_disabled" {
		t.Fatalf("expected *FeatureDisabled(403/feature_disabled), got %v", err)
	}
	if fd.Message != "Feature 'platform.sso' is not enabled for this organization's plan." {
		t.Fatalf("unexpected message: %q", fd.Message)
	}
}

func TestRequireFeature_Absent403(t *testing.T) {
	err := (&Gates{}).RequireFeature(Entitlements{Features: map[string]FeatureEntry{}}, "missing")
	var fd *FeatureDisabled
	if !errors.As(err, &fd) {
		t.Fatalf("absent feature should be FeatureDisabled, got %v", err)
	}
}

func TestRequireFeature_ValueFallback(t *testing.T) {
	// No enabled field -> fall back to value truthiness.
	ent := Entitlements{Features: map[string]FeatureEntry{"x": {Value: true}}}
	if err := (&Gates{}).RequireFeature(ent, "x"); err != nil {
		t.Fatalf("value:true should pass, got %v", err)
	}
}

// ---- gate 5: quota ----------------------------------------------------------

func quotaEnt(limit any) Entitlements {
	return Entitlements{Features: map[string]FeatureEntry{
		"max_projects": {Enabled: ptrBool(true), Config: map[string]any{"limit": limit}},
	}}
}

func TestEnforceQuota_Under(t *testing.T) {
	limit, err := (&Gates{}).EnforceQuota(quotaEnt(float64(25)), "max_projects", 10)
	if err != nil {
		t.Fatalf("under quota should pass, got %v", err)
	}
	if limit != 25 {
		t.Fatalf("expected limit 25, got %d", limit)
	}
}

func TestEnforceQuota_Over429(t *testing.T) {
	_, err := (&Gates{}).EnforceQuota(quotaEnt(float64(25)), "max_projects", 25, 1)
	var qe *QuotaExceeded
	if !errors.As(err, &qe) || qe.HTTPStatus() != 429 || qe.Kind() != "quota_exceeded" {
		t.Fatalf("expected *QuotaExceeded(429), got %v", err)
	}
	if qe.Current != 25 || qe.Limit != 25 || qe.Cost != 1 {
		t.Fatalf("unexpected fields: %+v", qe)
	}
	if qe.Message != "Quota 'max_projects' exceeded (26/25)." {
		t.Fatalf("unexpected message: %q", qe.Message)
	}
}

func TestEnforceQuota_BoundaryAllows(t *testing.T) {
	// current+cost == limit must pass (only strictly greater fails).
	if _, err := (&Gates{}).EnforceQuota(quotaEnt(float64(25)), "max_projects", 24, 1); err != nil {
		t.Fatalf("boundary should pass, got %v", err)
	}
}

func TestEnforceQuota_Unlimited(t *testing.T) {
	limit, err := (&Gates{}).EnforceQuota(quotaEnt(float64(-1)), "max_projects", 9999)
	if err != nil {
		t.Fatalf("unlimited (-1) should pass, got %v", err)
	}
	if limit != -1 {
		t.Fatalf("expected -1, got %d", limit)
	}
}

func TestEnforceQuota_Unconfigured(t *testing.T) {
	// Feature present but no limit in config -> allow, returns 0.
	ent := Entitlements{Features: map[string]FeatureEntry{"projects": {Enabled: ptrBool(true), Config: map[string]any{}}}}
	limit, err := (&Gates{}).EnforceQuota(ent, "projects", 100)
	if err != nil {
		t.Fatalf("unconfigured quota should allow, got %v", err)
	}
	if limit != 0 {
		t.Fatalf("expected 0, got %d", limit)
	}
}

func TestEnforceQuota_MissingFeature(t *testing.T) {
	// Feature absent entirely -> no limit present -> allow, returns 0.
	limit, err := (&Gates{}).EnforceQuota(Entitlements{Features: map[string]FeatureEntry{}}, "ghost", 5)
	if err != nil {
		t.Fatalf("missing feature should allow, got %v", err)
	}
	if limit != 0 {
		t.Fatalf("expected 0, got %d", limit)
	}
}

func TestEnforceQuota_NonIntegerLimit503(t *testing.T) {
	_, err := (&Gates{}).EnforceQuota(quotaEnt(12.5), "max_projects", 1)
	var ua *Unavailable
	if !errors.As(err, &ua) || ua.HTTPStatus() != 503 {
		t.Fatalf("expected *Unavailable(503) for non-integer limit, got %v", err)
	}
}

func TestEnforceQuota_DefaultCost(t *testing.T) {
	// cost defaults to 1: current 24, +1 == 25 == limit -> allow.
	if _, err := (&Gates{}).EnforceQuota(quotaEnt(float64(25)), "max_projects", 24); err != nil {
		t.Fatalf("default cost boundary should pass, got %v", err)
	}
	// current 25, +1 -> over.
	_, err := (&Gates{}).EnforceQuota(quotaEnt(float64(25)), "max_projects", 25)
	var qe *QuotaExceeded
	if !errors.As(err, &qe) {
		t.Fatalf("default cost over should fail, got %v", err)
	}
}

func TestEnforceQuota_ConfigValueFallback(t *testing.T) {
	// No config.limit, but config.value present -> used as limit.
	ent := Entitlements{Features: map[string]FeatureEntry{
		"seats": {Enabled: ptrBool(true), Config: map[string]any{"value": float64(3)}},
	}}
	limit, err := (&Gates{}).EnforceQuota(ent, "seats", 2)
	if err != nil {
		t.Fatalf("config.value fallback should pass, got %v", err)
	}
	if limit != 3 {
		t.Fatalf("expected 3, got %d", limit)
	}
}

// ---- GateError interface ----------------------------------------------------

func TestErrorsImplementGateError(t *testing.T) {
	var errs = []GateError{
		&Unauthenticated{}, &PermissionDenied{}, &SubscriptionInactive{},
		&FeatureDisabled{}, &QuotaExceeded{}, &Unavailable{},
	}
	wantStatus := []int{401, 403, 402, 403, 429, 503}
	for i, e := range errs {
		if e.HTTPStatus() != wantStatus[i] {
			t.Fatalf("%s: status %d != %d", e.Kind(), e.HTTPStatus(), wantStatus[i])
		}
		// must satisfy errors.As against its own concrete type via GateError too.
		var ge GateError
		if !errors.As(error(e), &ge) {
			t.Fatalf("errors.As GateError failed for %s", e.Kind())
		}
	}
}

// ---- constructor validation -------------------------------------------------

func TestNew_Validation(t *testing.T) {
	c, _ := egavsdk.New(egavsdk.Config{ServiceURLs: map[string]string{"control-plane": "http://x", "authz": "http://x"}})
	if _, err := New(Config{Client: nil, CPAPIKey: "a", AuthZAPIKey: "b"}); err == nil {
		t.Fatal("expected error for nil client")
	}
	if _, err := New(Config{Client: c, AuthZAPIKey: "b"}); err == nil {
		t.Fatal("expected error for missing CP key")
	}
	if _, err := New(Config{Client: c, CPAPIKey: "a"}); err == nil {
		t.Fatal("expected error for missing AuthZ key")
	}
}
