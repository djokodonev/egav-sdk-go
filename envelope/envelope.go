// Package envelope mirrors the EGAV platform wire envelopes so consumers get
// typed success payloads and typed errors.
//
// Every EGAV service wraps success responses in egav_base.BaseResponse and
// errors in egav_base.ErrorResponse (Quality Rule 5.1). This package decodes
// both: success -> BaseResponse[T], error (status >= 400) -> *APIError.
package envelope

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Meta is the pagination metadata block on list responses.
type Meta struct {
	Total      int `json:"total,omitempty"`
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// BaseResponse mirrors egav_base.BaseResponse — the success envelope.
type BaseResponse[T any] struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success"`
	Status  string `json:"status"`
	Data    *T     `json:"data,omitempty"`
	Meta    *Meta  `json:"meta,omitempty"`
}

// ErrorResponse mirrors egav_base.ErrorResponse (Rule 5.1). request_payload is
// deliberately absent on the server side (Rule 5.2) and never expected here.
type ErrorResponse struct {
	ErrorCode int    `json:"error_code"`
	Message   string `json:"message"`
	Success   bool   `json:"success"`
	Status    string `json:"status"`
}

// APIError is returned whenever a service responds with HTTP >= 400. It carries
// both the HTTP status and the platform's machine-readable error_code so callers
// can branch on either.
type APIError struct {
	StatusCode int
	ErrorCode  int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("egav: http %d (error_code=%d): %s", e.StatusCode, e.ErrorCode, e.Message)
}

const maxBody = 10 << 20 // 10 MiB guard against unbounded response bodies.

// Decode reads an HTTP response and returns either a typed BaseResponse[T] on
// success or an *APIError on a >= 400 status. The response body is always closed.
func Decode[T any](resp *http.Response) (*BaseResponse[T], error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("egav: read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		var er ErrorResponse
		_ = json.Unmarshal(body, &er) // best-effort; some upstreams may not envelope
		msg := er.Message
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{StatusCode: resp.StatusCode, ErrorCode: er.ErrorCode, Message: msg}
	}
	var out BaseResponse[T]
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("egav: decode response: %w", err)
	}
	return &out, nil
}
