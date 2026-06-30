package gates

import "fmt"

// GateError is the common interface for every access-gate failure. Each concrete
// error carries the HTTP status a handler should return plus a machine-readable
// kind/error_code, so a handler can map a denied gate straight to a response
// without inspecting the gate's internals.
//
// Every gate error implements error, so errors.As / errors.Is work against the
// concrete types below.
type GateError interface {
	error
	// HTTPStatus is the response status this failure maps to (401/402/403/429/503).
	HTTPStatus() int
	// Kind is a stable machine-readable discriminator ("unauthenticated",
	// "permission_denied", "subscription_inactive", "feature_disabled",
	// "quota_exceeded", "unavailable").
	Kind() string
}

// Action is an optional remediation hint the caller can surface to the end user
// (e.g. a "Renew subscription" button pointing at /billing/plans). It mirrors
// the gate-action object the Python feature gates emit.
type Action struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	URL   string `json:"url,omitempty"`
}

// Unauthenticated — gate 1 failed: the end-user bearer was missing/invalid.
// HTTP 401.
type Unauthenticated struct {
	Message string
}

func (e *Unauthenticated) Error() string  { return e.Message }
func (e *Unauthenticated) HTTPStatus() int { return 401 }
func (e *Unauthenticated) Kind() string    { return "unauthenticated" }

// PermissionDenied — gate 2 failed: AuthZ denied the action. HTTP 403,
// error_code 4031.
type PermissionDenied struct {
	PermissionCode string
	Message        string
}

func (e *PermissionDenied) Error() string  { return e.Message }
func (e *PermissionDenied) HTTPStatus() int { return 403 }
func (e *PermissionDenied) ErrorCode() int  { return 4031 }
func (e *PermissionDenied) Kind() string    { return "permission_denied" }

// SubscriptionInactive — gate 3 failed: the org's subscription is not active.
// HTTP 402.
type SubscriptionInactive struct {
	Reason  string
	Message string
	Action  *Action
}

func (e *SubscriptionInactive) Error() string  { return e.Message }
func (e *SubscriptionInactive) HTTPStatus() int { return 402 }
func (e *SubscriptionInactive) Kind() string    { return "subscription_inactive" }

// FeatureDisabled — gate 4 failed: the org's plan does not enable the feature.
// HTTP 403, kind "feature_disabled".
type FeatureDisabled struct {
	Code    string
	Message string
}

func (e *FeatureDisabled) Error() string  { return e.Message }
func (e *FeatureDisabled) HTTPStatus() int { return 403 }
func (e *FeatureDisabled) Kind() string    { return "feature_disabled" }

// QuotaExceeded — gate 5 failed: the org would exceed its plan limit. HTTP 429,
// kind "quota_exceeded".
type QuotaExceeded struct {
	Code    string
	Current int
	Limit   int
	Cost    int
	Message string
}

func (e *QuotaExceeded) Error() string  { return e.Message }
func (e *QuotaExceeded) HTTPStatus() int { return 429 }
func (e *QuotaExceeded) Kind() string    { return "quota_exceeded" }

// Unavailable — a required dependency (CP / AuthZ) was unreachable or returned
// an unusable response. Gates FAIL CLOSED: this is raised rather than
// default-allowing. HTTP 503.
type Unavailable struct {
	Message string
}

func (e *Unavailable) Error() string  { return e.Message }
func (e *Unavailable) HTTPStatus() int { return 503 }
func (e *Unavailable) Kind() string    { return "unavailable" }

// unavailablef builds an *Unavailable with a formatted message.
func unavailablef(format string, args ...any) *Unavailable {
	return &Unavailable{Message: fmt.Sprintf(format, args...)}
}
