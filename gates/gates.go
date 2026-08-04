// Package gates implements the five EGAV access gates a server-side app applies
// to protect an endpoint, on top of the consumer SDK's authed HTTP Client. It is
// the Go port of the Python egav-app-sdk decorators + egav-cp-client feature
// gates, so an app written in any language leverages the platform identically.
//
// The five gates, in the order a handler applies them:
//
//  1. auth                 — validate the inbound end-user bearer -> Identity.
//  2. permission           — AuthZ says the user may do the action.
//  3. subscription-active  — the org's subscription is active.
//  4. feature              — the org's plan enables the feature.
//  5. quota                — the org is under its plan limit for the metric.
//
// Two credentials, correct trust model (not a shortcut): the end-user bearer is
// used ONLY for gate 1 (portal/me); the app's service x-api-key is used for
// gates 2–5 (the /internal/* endpoints are service-to-service). The user bearer
// is never sent to /internal/*, and the app key is never sent to /portal/*.
//
// All gates FAIL CLOSED: an unreachable CP/AuthZ or an unusable response raises
// *Unavailable (HTTP 503) rather than default-allowing.
package gates

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	egavsdk "github.com/djokodonev/egav-sdk-go"
	"github.com/djokodonev/egav-sdk-go/envelope"
)

// App codes the gates resolve against the SDK Client's ServiceURLs map.
const (
	appControlPlane = "control-plane"
	appAuthZ        = "authz"
)

// Identity is the authenticated principal returned by gate 1.
type Identity struct {
	UserGuid string `json:"user_guid"`
	OrgGuid  string `json:"org_guid"`
}

// FeatureEntry is one feature's record inside the effective-features payload.
type FeatureEntry struct {
	Enabled *bool          `json:"enabled,omitempty"`
	Value   any            `json:"value,omitempty"`
	Config  map[string]any `json:"config,omitempty"`
}

// Gate is the optional access-gate object on the effective-features payload. It
// may be absent on older CP versions, in which case subscription status drives
// gate 3.
type Gate struct {
	Access  string  `json:"access,omitempty"` // "ok" | "blocked"
	Reason  string  `json:"reason,omitempty"`
	Message string  `json:"message,omitempty"`
	Action  *Action `json:"action,omitempty"`
}

// Entitlements is the org's effective entitlements fetched once per request from
// CP. Gates 3/4/5 are pure functions over this value (mirrors the Python
// get_org_features-once pattern).
type Entitlements struct {
	PlanCode           string                  `json:"plan_code,omitempty"`
	PlanTier           string                  `json:"plan_tier,omitempty"`
	SubscriptionStatus string                  `json:"subscription_status,omitempty"`
	Gate               *Gate                   `json:"gate,omitempty"`
	Features           map[string]FeatureEntry `json:"features,omitempty"`
}

// Gates applies the five access gates against the platform. Construct one with
// New and reuse it for the life of the process; it is safe for concurrent use
// (it holds no per-request state).
type Gates struct {
	client   *egavsdk.Client
	cpKey    string
	authzKey string
}

// Config configures a Gates value.
type Config struct {
	// Client is the SDK HTTP client. Its ServiceURLs MUST contain "control-plane"
	// and "authz" entries (the gates resolve those app codes).
	Client *egavsdk.Client

	// CPAPIKey is the app's inbound x-api-key for Control Plane /internal/* calls.
	CPAPIKey string

	// AuthZAPIKey is the app's inbound x-api-key for AuthZ /internal/* calls.
	AuthZAPIKey string
}

// New validates config and returns a Gates.
func New(cfg Config) (*Gates, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("gates: Client is required")
	}
	if cfg.CPAPIKey == "" {
		return nil, fmt.Errorf("gates: CPAPIKey is required (x-api-key for control-plane /internal/*)")
	}
	if cfg.AuthZAPIKey == "" {
		return nil, fmt.Errorf("gates: AuthZAPIKey is required (x-api-key for authz /internal/*)")
	}
	return &Gates{
		client:   cfg.Client,
		cpKey:    cfg.CPAPIKey,
		authzKey: cfg.AuthZAPIKey,
	}, nil
}

// Authenticate is gate 1: it validates the inbound end-user bearer against CP's
// portal/me and returns the resolved Identity. The bearer is sent ONLY here.
//
//   - 200 -> Identity{UserGuid, OrgGuid}.
//   - 401 -> *Unauthenticated.
//   - 5xx / transport -> *Unavailable (fail closed).
func (g *Gates) Authenticate(ctx context.Context, userBearer string) (Identity, error) {
	if strings.TrimSpace(userBearer) == "" {
		return Identity{}, &Unauthenticated{Message: "Missing or empty bearer token."}
	}
	resp, err := g.client.DoRaw(ctx, appControlPlane, http.MethodGet,
		"/v1/control-plane/portal/me", nil,
		map[string]string{"Authorization": "Bearer " + userBearer})
	if err != nil {
		return Identity{}, unavailablef("gates: control-plane unreachable: %v", err)
	}
	out, derr := envelope.Decode[Identity](resp)
	if derr != nil {
		var apiErr *envelope.APIError
		if errors.As(derr, &apiErr) {
			if apiErr.StatusCode == http.StatusUnauthorized {
				return Identity{}, &Unauthenticated{Message: "Invalid or expired credentials."}
			}
			if apiErr.StatusCode >= 500 {
				return Identity{}, unavailablef("gates: control-plane error (status %d).", apiErr.StatusCode)
			}
		}
		return Identity{}, unavailablef("gates: portal/me failed: %v", derr)
	}
	if out.Data == nil || out.Data.UserGuid == "" || out.Data.OrgGuid == "" {
		return Identity{}, unavailablef("gates: portal/me returned an empty identity.")
	}
	return *out.Data, nil
}

// RequirePermission is gate 2: it asks AuthZ whether the user may perform the
// action derived from permissionCode (the substring after the last "."), against
// resourceType (default "app"). FAILS CLOSED on any AuthZ error.
//
//   - allowed:true  -> nil.
//   - allowed:false -> *PermissionDenied (403, error_code 4031).
//   - transport/5xx -> *Unavailable (503).
func (g *Gates) RequirePermission(ctx context.Context, id Identity, permissionCode string, resourceType ...string) error {
	rt := "app"
	if len(resourceType) > 0 && resourceType[0] != "" {
		rt = resourceType[0]
	}
	action := permissionCode
	if idx := strings.LastIndex(permissionCode, "."); idx >= 0 {
		action = permissionCode[idx+1:]
	}
	body := map[string]any{
		"user_guid":     id.UserGuid,
		"org_guid":      id.OrgGuid,
		"action":        action,
		"resource_type": rt,
	}
	resp, err := g.client.DoRaw(ctx, appAuthZ, http.MethodPost,
		"/v1/authz/internal/authorize", body,
		map[string]string{"x-api-key": g.authzKey})
	if err != nil {
		return unavailablef("gates: authz unreachable: %v", err)
	}
	type authzDecision struct {
		Allowed bool `json:"allowed"`
	}
	// AuthZ returns the decision either bare or inside a BaseResponse data block;
	// decode into the envelope and fall back to the bare shape.
	out, derr := envelope.Decode[authzDecision](resp)
	if derr != nil {
		var apiErr *envelope.APIError
		if errors.As(derr, &apiErr) && apiErr.StatusCode >= 500 {
			return unavailablef("gates: authz error (status %d).", apiErr.StatusCode)
		}
		return unavailablef("gates: authorize failed: %v", derr)
	}
	if out.Data == nil {
		return unavailablef("gates: authorize returned no decision.")
	}
	if !out.Data.Allowed {
		return &PermissionDenied{
			PermissionCode: permissionCode,
			Message:        "Permission denied: " + permissionCode,
		}
	}
	return nil
}

// Entitlements is the gates 3–5 fetch: ONE CP call into an Entitlements value.
// FAILS CLOSED — empty/{}/transport/5xx all raise *Unavailable; never
// default-allow.
func (g *Gates) Entitlements(ctx context.Context, orgGuid string) (Entitlements, error) {
	if strings.TrimSpace(orgGuid) == "" {
		return Entitlements{}, unavailablef("gates: orgGuid is required.")
	}
	path := "/v1/control-plane/internal/organizations/" + orgGuid + "/effective-features"
	resp, err := g.client.DoRaw(ctx, appControlPlane, http.MethodGet, path, nil,
		map[string]string{"x-api-key": g.cpKey})
	if err != nil {
		return Entitlements{}, unavailablef("gates: control-plane unreachable: %v", err)
	}
	out, derr := envelope.Decode[Entitlements](resp)
	if derr != nil {
		var apiErr *envelope.APIError
		if errors.As(derr, &apiErr) && apiErr.StatusCode >= 500 {
			return Entitlements{}, unavailablef("gates: control-plane error (status %d).", apiErr.StatusCode)
		}
		return Entitlements{}, unavailablef("gates: effective-features failed: %v", derr)
	}
	if out.Data == nil {
		return Entitlements{}, unavailablef("gates: effective-features returned an empty payload.")
	}
	ent := *out.Data
	// An entitlements payload with no status, no gate and no features is an
	// unusable/empty response — fail closed rather than treating it as allow.
	if ent.SubscriptionStatus == "" && ent.Gate == nil && len(ent.Features) == 0 {
		return Entitlements{}, unavailablef("gates: effective-features returned no entitlements.")
	}
	return ent, nil
}

// RequireActiveSubscription is gate 3: it passes when the org's subscription is
// active, otherwise raises *SubscriptionInactive (402).
func (g *Gates) RequireActiveSubscription(ent Entitlements) error {
	if ent.Gate != nil && ent.Gate.Access == "blocked" {
		reason := ent.Gate.Reason
		if reason == "" {
			reason = "subscription_inactive"
		}
		message := ent.Gate.Message
		if message == "" {
			message = "Your subscription is not active. Renew to restore access."
		}
		return &SubscriptionInactive{Reason: reason, Message: message, Action: ent.Gate.Action}
	}
	switch ent.SubscriptionStatus {
	case "active", "trialing":
		return nil
	default:
		return &SubscriptionInactive{
			Reason:  "subscription_inactive",
			Message: "Your subscription is not active. Renew to restore access.",
			Action:  &Action{Kind: "renew", Label: "Renew subscription", URL: "/billing/plans"},
		}
	}
}

// RequireFeature is gate 4: it passes when the named feature is enabled on the
// org's plan, otherwise raises *FeatureDisabled (403, kind "feature_disabled").
func (g *Gates) RequireFeature(ent Entitlements, code string) error {
	feat, ok := ent.Features[code]
	if ok && featureEnabled(feat) {
		return nil
	}
	return &FeatureDisabled{
		Code:    code,
		Message: fmt.Sprintf("Feature '%s' is not enabled for this organization's plan.", code),
	}
}

// EnforceQuota is gate 5: it returns the resolved limit when current+cost is
// within it (cost defaults to 1), otherwise raises *QuotaExceeded (429).
//
//   - limit unset            -> returns 0 (no quota configured -> allow).
//   - limit non-integer      -> *Unavailable (misconfig, fail closed).
//   - limit < 0              -> returns limit (unlimited -> allow).
//   - current+cost > limit   -> *QuotaExceeded.
//   - else                   -> returns limit (allow).
//
// This is the simple hard-cap path; the Python policy/grace/overage branches are
// out of scope for v1 (the static cap is exactly enforce_quota's default when no
// policy resolves).
func (g *Gates) EnforceQuota(ent Entitlements, code string, current int, cost ...int) (int, error) {
	c := 1
	if len(cost) > 0 {
		c = cost[0]
	}
	raw, present := extractLimit(ent.Features[code])
	if !present {
		return 0, nil // no quota configured -> allow.
	}
	limit, ok := toInt(raw)
	if !ok {
		return 0, unavailablef("gates: quota '%s' has a non-integer limit.", code)
	}
	if limit < 0 {
		return limit, nil // unlimited.
	}
	if current+c > limit {
		return 0, &QuotaExceeded{
			Code:    code,
			Current: current,
			Limit:   limit,
			Cost:    c,
			Message: fmt.Sprintf("Quota '%s' exceeded (%d/%d).", code, current+c, limit),
		}
	}
	return limit, nil
}

// featureEnabled mirrors the Python truthiness: prefer enabled, fall back to value.
func featureEnabled(f FeatureEntry) bool {
	if f.Enabled != nil {
		return *f.Enabled
	}
	return truthy(f.Value)
}

// extractLimit resolves a quota limit from a feature entry in the same order as
// the Python _extract_limit: config.limit, then config.value, then the bare
// value. The bool reports whether a numeric limit value was present at all.
//
// A bare boolean `enabled` is NOT a quota value — a feature that is merely
// enabled with no config carries no numeric limit, so we report "not present"
// and the caller treats that as unconfigured (allow). Only an explicit
// config.limit / config.value / a numeric bare value counts as a limit.
func extractLimit(f FeatureEntry) (any, bool) {
	if f.Config != nil {
		if v, ok := f.Config["limit"]; ok && v != nil {
			return v, true
		}
		if v, ok := f.Config["value"]; ok && v != nil {
			return v, true
		}
	}
	if f.Value != nil {
		if _, isBool := f.Value.(bool); !isBool {
			return f.Value, true
		}
	}
	return nil, false
}

// toInt coerces a JSON-decoded number/bool into an int, reporting whether the
// value is a usable integer. JSON numbers decode to float64; a fractional value
// is rejected as non-integer (fail closed at the call site).
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case bool:
		// A bare boolean "enabled" is not a numeric limit.
		return 0, false
	default:
		return 0, false
	}
}

// truthy reports the Python-style truthiness of a JSON-decoded feature value.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != "" && t != "false" && t != "0"
	default:
		return true
	}
}
