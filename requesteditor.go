package egavsdk

import (
	"context"
	"net/http"

	"github.com/getek/egav-sdk-go/auth"
)

// BearerEditor returns an oapi-codegen-compatible RequestEditorFn that injects
// a fresh "Authorization: Bearer <token>" header from the TokenSource on every
// request. Pass it to a generated client via its WithRequestEditorFn option:
//
//	cli, _ := automation.NewClientWithResponses(
//	    baseURL,
//	    automation.WithHTTPClient(httpClient),
//	    automation.WithRequestEditorFn(egavsdk.BearerEditor(ts)),
//	)
//
// The returned func has an unnamed type assignable to each generated package's
// RequestEditorFn, so it works across services without an import cycle.
func BearerEditor(ts auth.TokenSource) func(ctx context.Context, req *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		if ts == nil {
			return nil
		}
		tok, err := ts.Token(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
}

// HeaderEditor returns a RequestEditorFn that sets static headers (e.g.
// X-App-Instance-Guid, X-App-Code) on every request.
func HeaderEditor(headers map[string]string) func(ctx context.Context, req *http.Request) error {
	return func(_ context.Context, req *http.Request) error {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return nil
	}
}
