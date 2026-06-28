package envelope

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func mkResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type org struct {
	GUID string `json:"guid"`
	Name string `json:"name"`
}

func TestDecodeSuccess(t *testing.T) {
	resp := mkResp(200, `{"success":true,"status":"success","data":{"guid":"g-1","name":"Acme"}}`)
	out, err := Decode[org](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Success || out.Data == nil || out.Data.Name != "Acme" {
		t.Fatalf("unexpected payload: %+v", out)
	}
}

func TestDecodeError(t *testing.T) {
	resp := mkResp(404, `{"success":false,"status":"error","error_code":404,"message":"Not found"}`)
	_, err := Decode[org](resp)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != 404 || apiErr.ErrorCode != 404 || apiErr.Message != "Not found" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}

func TestDecodeErrorWithoutEnvelope(t *testing.T) {
	// Some upstreams (proxies) may return a non-enveloped 503 — still an APIError.
	resp := mkResp(503, `Service Unavailable`)
	_, err := Decode[org](resp)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 503 || apiErr.Message == "" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}
