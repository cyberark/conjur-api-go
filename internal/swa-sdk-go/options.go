package swa

import (
	"io"
	"net/http"
	"time"
)

// DefaultTimeout is the per-request timeout applied when the caller does not
// supply their own *http.Client. It matches the timeout used by the existing
// SWA control-plane clients.
const DefaultTimeout = 30 * time.Second

// DefaultMediaType is the versioned Secrets Manager JSON media type the SWA
// control plane speaks.
const DefaultMediaType = "application/x.secretsmgr.v2+json"

// Option configures a Client. Options follow the functional-options pattern used
// throughout the Go ecosystem (aws-sdk-go-v2, grpc-go), giving a stable,
// backwards-compatible constructor surface.
type Option func(*config)

// config is the fully-resolved, internal client configuration.
type config struct {
	baseURL     string
	httpClient  *http.Client
	transport   http.RoundTripper
	timeout     time.Duration
	userAgent   string
	mediaType   string
	authScheme  authScheme
	tokenSource TokenSource
	editors     []RequestEditorFn
	retry       RetryPolicy
	debugOut    io.Writer
}

func defaultConfig() config {
	return config{
		timeout:    DefaultTimeout,
		mediaType:  DefaultMediaType,
		userAgent:  defaultUserAgent(),
		authScheme: authNone,
	}
}

// WithBaseURL sets the control-plane base URL, for example
// "https://example.secretsmgr.cyberark.cloud". A trailing slash and a trailing
// "/api" segment are trimmed automatically, so URLs taken from a Conjur CLI
// configuration (which include "/api") work as-is.
func WithBaseURL(baseURL string) Option {
	return func(c *config) { c.baseURL = baseURL }
}

// WithHTTPClient supplies a custom *http.Client. Its Transport and Timeout are
// respected. If you also pass WithRoundTripper or WithTimeout, those refine this
// client rather than replacing it.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithRoundTripper installs a custom transport, typically an authentication
// RoundTripper (for example the auth/conjur adapter) that
// signs or injects credentials on every request.
func WithRoundTripper(rt http.RoundTripper) Option {
	return func(c *config) { c.transport = rt }
}

// WithTimeout sets the per-request timeout. Ignored if a caller-supplied
// *http.Client already defines a non-zero Timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithUserAgent overrides the User-Agent header sent on every request.
func WithUserAgent(ua string) Option {
	return func(c *config) { c.userAgent = ua }
}

// WithMediaType overrides the Accept media type. Most callers should not need
// this; it exists for forward compatibility with future API versions.
func WithMediaType(mt string) Option {
	return func(c *config) {
		if mt != "" {
			c.mediaType = mt
		}
	}
}

// WithConjurToken authenticates using a static Conjur access token, sending it
// as `Authorization: Token token="<token>"`. Prefer WithTokenSource (or the
// auth/conjur adapter) when tokens expire and need refreshing.
func WithConjurToken(token string) Option {
	return func(c *config) {
		c.authScheme = authConjurToken
		c.tokenSource = staticTokenSource(token)
	}
}

// WithBearerToken authenticates using a static bearer token, sending it as
// `Authorization: Bearer <token>`.
func WithBearerToken(token string) Option {
	return func(c *config) {
		c.authScheme = authBearer
		c.tokenSource = staticTokenSource(token)
	}
}

// WithTokenSource authenticates using a TokenSource consulted on every request,
// so token refresh is transparent. The token is sent using the Conjur
// `Token token="..."` scheme, which is what the SWA control plane expects.
func WithTokenSource(source TokenSource) Option {
	return func(c *config) {
		c.authScheme = authConjurToken
		c.tokenSource = source
	}
}

// WithBearerTokenSource is like WithTokenSource but sends the resolved token
// using the `Bearer` scheme.
func WithBearerTokenSource(source TokenSource) Option {
	return func(c *config) {
		c.authScheme = authBearer
		c.tokenSource = source
	}
}

// WithRequestEditors appends custom request editors, run after the SDK's
// built-in editors on every request. Use these for extra headers or tracing.
func WithRequestEditors(editors ...RequestEditorFn) Option {
	return func(c *config) { c.editors = append(c.editors, editors...) }
}

// WithRetry enables automatic retries of idempotent operations using the given
// policy. Pass DefaultRetryPolicy() for sensible defaults.
func WithRetry(policy RetryPolicy) Option {
	return func(c *config) { c.retry = policy }
}

// WithDebug logs each request and response to w with sensitive headers redacted.
// Intended for development only.
func WithDebug(w io.Writer) Option {
	return func(c *config) { c.debugOut = w }
}
