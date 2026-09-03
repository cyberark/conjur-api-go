package swa

import (
	"math"
	"net/http"
	"time"
)

// RetryPolicy controls automatic retries for transient failures. Retries are
// only ever applied to idempotent operations (GET/PUT/PATCH/DELETE-style reads
// and updates and, in this API, the idempotent PATCH/DELETE endpoints). POST
// creates are never retried automatically because they are not guaranteed to be
// idempotent.
//
// The zero value disables retries. Use DefaultRetryPolicy for sensible
// exponential backoff.
type RetryPolicy struct {
	// MaxRetries is the number of additional attempts after the first. Zero
	// disables retries.
	MaxRetries int
	// BaseDelay is the delay before the first retry; it doubles each attempt.
	BaseDelay time.Duration
	// MaxDelay caps the per-attempt backoff.
	MaxDelay time.Duration
}

// DefaultRetryPolicy is a conservative exponential-backoff policy suitable for
// most callers: up to 3 retries starting at 200ms and capping at 5s.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxRetries: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second}
}

// enabled reports whether the policy performs any retries.
func (p RetryPolicy) enabled() bool { return p.MaxRetries > 0 }

// backoff returns the delay before the given attempt number (1-indexed).
func (p RetryPolicy) backoff(attempt int) time.Duration {
	base := p.BaseDelay
	if base <= 0 {
		base = 200 * time.Millisecond
	}
	d := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	if p.MaxDelay > 0 && d > p.MaxDelay {
		d = p.MaxDelay
	}
	return d
}

// retryableStatus reports whether an HTTP status warrants a retry.
//
// 500 is included: the client only ever retries operations it has marked
// idempotent (see execute's idempotent flag — GET/PATCH/DELETE, never POST
// creates), so re-issuing on a transient server error is safe and lets callers
// ride out a brief backend hiccup rather than failing the whole reconcile.
func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
