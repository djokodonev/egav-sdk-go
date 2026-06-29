# egav-sdk-go

Go **consumer** SDK for the EGAV / SynaptaGrid platform. It covers the two
client-side tiers:

1. **Auth** — `auth.CredentialsTokenManager` logs in against AuthN and keeps the
   access token fresh (refresh-token rotation, fall back to re-login).
2. **Typed REST access** — `egavsdk.Client` is an authenticated, retrying JSON
   client; `Get[T]` / `Post[T]` decode the platform's `BaseResponse[T]`
   envelope and turn any `>= 400` into a typed `*envelope.APIError`.

It is **not** the app-building SDK — there is no app factory, tenant
middleware, outbox, or scoped CRUD. Those live in the Python (`egav-app-sdk`)
and TypeScript (`@egav/app-sdk`) app SDKs. This package is for programs that
*consume* the platform from Go.

## Status

Hand-written core (auth + client + envelope), unit-tested. The full per-service
typed surface is intended to be generated from each service's `/openapi.json`
with `oapi-codegen` (see *Roadmap*).

## Build & test (no host Go needed)

Everything runs in the `golang:1.23` Docker image:

```bash
make check      # go vet + go test
make build
make test
```

## Usage

```go
// Portal login is the OIDC headless flow (PKCE). ClientID/RedirectURI come
// from a registered public OIDC client (CP config).
tm, _ := auth.NewOIDCHeadlessManager(auth.OIDCConfig{
    AuthNBaseURL: "https://authn-api.local.synaptagrid.io:5209",
    ClientID:     "public_web_67a894b8cb0e",
    RedirectURI:  "https://local.synaptagrid.io:3200/callback",
    Email:        os.Getenv("EGAV_TEST_EMAIL"),
    Password:     os.Getenv("EGAV_TEST_PASSWORD"),
    HTTPClient:   insecureClient, // local self-signed certs
})

c, _ := egavsdk.New(egavsdk.Config{
    ServiceURLs: map[string]string{
        "control-plane": "https://cp-api.local.synaptagrid.io:5207",
        "authz":         "https://authz-api.local.synaptagrid.io:5206",
    },
    TokenSource:        tm,
    InsecureSkipVerify: true, // local dev only
    DefaultHeaders:     map[string]string{"X-App-Instance-Guid": instanceGUID},
})

type Org struct {
    GUID string `json:"guid"`
    Name string `json:"name"`
}
res, err := egavsdk.Get[Org](ctx, c, "control-plane", "/v1/control-plane/portal/org")
```

## Generated clients

Typed per-service clients are generated from each service's OpenAPI spec into
`services/<svc>/`. The Automation client (`services/automation`) is generated
and compiled. Pipeline (all in Docker, no host Go):

```bash
make generate   # normalize 3.1 -> 3.0, then oapi-codegen, then go mod tidy
```

FastAPI emits OpenAPI **3.1**, which oapi-codegen v2 can't parse (the
`anyOf:[T,null]` nullable idiom). `tools/normalize_openapi.py` collapses that to
3.0 `nullable: true` first. Wire a generated client to auth/TLS with the
`BearerEditor` / `HeaderEditor` request editors (see `requesteditor.go`).

## Roadmap

- Generate the remaining service clients (CP, AuthN, AuthZ, …) the same way once
  their specs are exported.
- CloudEvents consumption via `github.com/cloudevents/sdk-go` (Rule 16.1 —
  adopt the standard, don't hand-roll the envelope).
- `x-api-key` service-to-service token source (alongside the portal-bearer one).
