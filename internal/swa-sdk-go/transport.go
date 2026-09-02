package swa

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// RequestEditorFn mutates an outgoing request before it is sent. It matches the
// signature the underlying generated clients expect, so custom editors compose
// cleanly with the SDK's built-in ones.
type RequestEditorFn = func(ctx context.Context, req *http.Request) error

// headerUserAgent is set on every request unless the caller already provided one.
func userAgentEditor(userAgent string) RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if userAgent != "" && req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", userAgent)
		}
		return nil
	}
}

// acceptEditor pins the Accept header to the versioned media type.
func acceptEditor(mediaType string) RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Accept", mediaType)
		return nil
	}
}

// authEditor writes the Authorization header. When a TokenSource is configured
// it is consulted per request (so refresh is transparent); otherwise nothing is
// done here and authentication is expected to come from a RoundTripper.
func authEditor(scheme authScheme, source TokenSource) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		if scheme == authNone || source == nil {
			return nil
		}
		// If a caller-supplied editor already set Authorization, respect it.
		if req.Header.Get("Authorization") != "" {
			return nil
		}
		token, err := source.Token(ctx)
		if err != nil {
			return fmt.Errorf("resolving access token: %w", err)
		}
		applyAuth(req, scheme, token)
		return nil
	}
}

// combineEditors folds several editors into one, short-circuiting on the first
// error. nil editors are skipped.
func combineEditors(editors ...RequestEditorFn) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		for _, e := range editors {
			if e == nil {
				continue
			}
			if err := e(ctx, req); err != nil {
				return err
			}
		}
		return nil
	}
}

// debugTransport is an optional RoundTripper wrapper that logs each request and
// response with sensitive headers redacted. It is enabled via WithDebug.
type debugTransport struct {
	base http.RoundTripper
	out  io.Writer
	// mu serializes writes to out. A *Client is safe for concurrent use, so
	// concurrent requests would otherwise interleave their debug lines mid-write
	// (fmt.Fprintf is not guaranteed to be a single atomic Write). This mirrors
	// how the standard library's log.Logger guards its output.
	mu sync.Mutex
}

// sensitiveHeaders are never written to the debug log in cleartext.
var sensitiveHeaders = map[string]struct{}{
	"Authorization": {},
	"Cookie":        {},
	"Set-Cookie":    {},
}

func redactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if _, ok := sensitiveHeaders[http.CanonicalHeaderKey(k)]; ok {
			out[k] = []string{"REDACTED"}
			continue
		}
		out[k] = v
	}
	return out
}

func (d *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := d.base
	if base == nil {
		base = http.DefaultTransport
	}
	d.logf("swa > %s %s %v\n", req.Method, req.URL.String(), redactHeaders(req.Header))
	resp, err := base.RoundTrip(req)
	if err != nil {
		d.logf("swa < error: %v\n", err)
		return nil, err
	}
	d.logf("swa < %d %s %v\n", resp.StatusCode, req.URL.Path, redactHeaders(resp.Header))
	return resp, nil
}

// logf writes a debug line under the mutex so concurrent requests cannot
// interleave their output.
func (d *debugTransport) logf(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.out, format, args...)
}
