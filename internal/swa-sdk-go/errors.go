package swa

import (
	"encoding/json"
	"net/http"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

// The SDK's public error surface — the typed errors and the status predicates
// (swaerrors.IsNotFound, swaerrors.AsAPIError, …) — lives in the swaerrors
// subpackage so it reads naturally at the call site and can be imported without
// pulling in the whole client. This file holds only the internal machinery that
// turns a response body into an *swaerrors.APIError.

// ErrorParser turns a non-success response body into an *swaerrors.APIError.
// Each API surface has its own body shape, so the client selects the right
// parser.
type ErrorParser func(op swaerrors.Op, status int, requestID string, body []byte) *swaerrors.APIError

// ParseStandardError handles the {code, message} error shape used by the
// SWA control-plane API.
func ParseStandardError(op swaerrors.Op, status int, requestID string, body []byte) *swaerrors.APIError {
	apiErr := &swaerrors.APIError{Op: op, StatusCode: status, RequestID: requestID, Body: body}
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		// Some public endpoints return {"error": "..."} instead.
		Error string `json:"error"`
	}
	if len(body) > 0 && json.Unmarshal(body, &payload) == nil {
		apiErr.Code = payload.Code
		apiErr.Message = payload.Message
		if apiErr.Message == "" {
			apiErr.Message = payload.Error
		}
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(status)
	}
	return apiErr
}
