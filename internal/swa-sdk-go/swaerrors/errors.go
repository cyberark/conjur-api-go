// Package swaerrors holds the SDK's public error surface: the typed errors every
// operation can return and the predicates for inspecting them.
//
// It lives in its own package so the predicates read naturally at the call site
// — swaerrors.IsNotFound(err) rather than swa.IsNotFound(err), where "swa" is the
// whole SDK — and so error handling can be imported without pulling in the full
// client. Two error types are exposed:
//
//   - *APIError, returned when the control plane responds with a non-success
//     status. Branch on it with the status predicates (IsNotFound, IsConflict, …)
//     or AsAPIError.
//   - *ValidationError, returned when the SDK rejects a request client-side,
//     before it is sent. Branch on it with AsValidationError.
//
// This mirrors the error ergonomics of the AWS SDK (typed API errors) and the
// Kubernetes client-go apierrors package (status-based predicates).
package swaerrors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Op is the type for SDK operation identifiers. Every operation tags its errors
// with a named Op constant (defined in the swaerrors package) so that callers
// and logs get a stable, human-readable handle: apiErr.Op == swaerrors.OpServersCreate.
//
// The type lives here so that *APIError and *ValidationError can carry it
// without callers needing to import the full client just for error handling.
// The catalog of Op values lives in ops.go in this package.
type Op string

// APIError is the single, typed error returned by every SDK operation when the
// control plane responds with a non-success status. It is deliberately
// transport-agnostic: callers should branch on the Is* helpers (or errors.As)
// rather than inspecting raw HTTP responses.
type APIError struct {
	// Op is the SDK operation that failed, e.g. swaerrors.OpTrustDomainsGet. It gives
	// callers and logs a stable, human-readable handle on the failure.
	// Every possible value is an Op* constant in the swaerrors package.
	Op Op
	// StatusCode is the HTTP status code returned by the control plane.
	StatusCode int
	// Code is the machine-readable, snake_case error code from the API body
	// (e.g. "trust_domain_not_found"). Empty if the body carried no code.
	Code string
	// Message is the human-readable error message from the API body.
	Message string
	// RequestID is the value of the X-Request-Id header echoed back by the
	// server (or sent by the client), useful for support and correlation.
	RequestID string
	// Details carries structured sub-errors if returned by the API.
	Details []ErrorDetail
	// Body is the raw, undecoded response body, retained for debugging.
	Body []byte
}

// ErrorDetail represents an individual error item within a structured error response.
type ErrorDetail struct {
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("swa: %s: %s (%s) [status=%d request_id=%s]", e.Op, e.Message, e.Code, e.StatusCode, e.RequestID)
	case e.Message != "":
		return fmt.Sprintf("swa: %s: %s [status=%d request_id=%s]", e.Op, e.Message, e.StatusCode, e.RequestID)
	default:
		return fmt.Sprintf("swa: %s: unexpected status %d [request_id=%s]", e.Op, e.StatusCode, e.RequestID)
	}
}

// NewAPIError constructs an *APIError with the given HTTP status, machine code,
// and message. It exists so tests and fault-injection doubles (see the swatest
// package) can produce errors that the Is* predicates recognise, without having
// to reach through the unexported parsing path. Op is left empty; set it on the
// returned value if a specific operation label is needed.
func NewAPIError(statusCode int, code, message string) *APIError {
	return &APIError{StatusCode: statusCode, Code: code, Message: message}
}

// AsAPIError extracts an *APIError from err, if present. It is a thin
// convenience wrapper over errors.As.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// statusIs reports whether err is an *APIError with the given HTTP status.
func statusIs(err error, status int) bool {
	apiErr, ok := AsAPIError(err)
	return ok && apiErr.StatusCode == status
}

// IsBadRequest reports whether err is a 400 Bad Request API error.
func IsBadRequest(err error) bool { return statusIs(err, http.StatusBadRequest) }

// IsUnauthorized reports whether err is a 401 Unauthorized API error.
func IsUnauthorized(err error) bool { return statusIs(err, http.StatusUnauthorized) }

// IsForbidden reports whether err is a 403 Forbidden API error.
func IsForbidden(err error) bool { return statusIs(err, http.StatusForbidden) }

// IsNotFound reports whether err is a 404 Not Found API error. This is the
// predicate callers most commonly need (e.g. to treat a missing resource as a
// no-op during reconciliation).
func IsNotFound(err error) bool { return statusIs(err, http.StatusNotFound) }

// IsConflict reports whether err is a 409 Conflict API error (e.g. the resource
// already exists, or cannot be deleted because it is in use).
func IsConflict(err error) bool { return statusIs(err, http.StatusConflict) }

// IsValidation reports whether err is a 422 Unprocessable Entity API error
// (business/validation failure).
func IsValidation(err error) bool { return statusIs(err, http.StatusUnprocessableEntity) }

// IsThrottled reports whether err is a 429 Too Many Requests API error.
func IsThrottled(err error) bool { return statusIs(err, http.StatusTooManyRequests) }

// IsServerError reports whether err is a 5xx server-side API error.
func IsServerError(err error) bool {
	apiErr, ok := AsAPIError(err)
	return ok && apiErr.StatusCode >= 500
}

// FieldViolation is a single field-level validation problem.
type FieldViolation struct {
	// Field is the offending field, in dotted path form (e.g. "attestation").
	Field string
	// Message explains what is wrong and, where useful, how to fix it.
	Message string
}

func (v FieldViolation) String() string { return v.Field + ": " + v.Message }

// ValidationError reports one or more client-side violations of the SWA API
// contract detected before a request was sent. It is distinct from *APIError
// (which represents a response from the server); callers can branch on it with
// errors.As(err, &vErr) or AsValidationError.
type ValidationError struct {
	// Op is the SDK operation that was validated, e.g. swaerrors.OpServerGroupsCreate.
	// Every possible value is an Op* constant in this package.
	Op Op
	// Violations is the non-empty list of problems found.
	Violations []FieldViolation
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		parts[i] = v.String()
	}
	return fmt.Sprintf("swa: %s: invalid request: %s", e.Op, strings.Join(parts, "; "))
}

// AsValidationError extracts a *ValidationError from err, if present.
func AsValidationError(err error) (*ValidationError, bool) {
	var vErr *ValidationError
	if errors.As(err, &vErr) {
		return vErr, true
	}
	return nil, false
}

// NewValidationError returns a *ValidationError for op, or nil when there are no
// violations (so callers can `return NewValidationError(...)` directly).
func NewValidationError(op Op, violations []FieldViolation) error {
	if len(violations) == 0 {
		return nil
	}
	return &ValidationError{Op: op, Violations: violations}
}
