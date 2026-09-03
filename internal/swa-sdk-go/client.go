package swa

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"

	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// Version is the SDK version, surfaced in the default User-Agent.
const Version = "0.1.0"

// ErrMissingBaseURL is returned by NewClient when no base URL is configured.
var ErrMissingBaseURL = errors.New("swa: base URL is required (use WithBaseURL)")

// Client is the entry point to the SWA SDK. It is safe for
// concurrent use by multiple goroutines. Construct one with NewClient and reach
// each API surface through its accessor (TrustDomains, ServerGroups, and so on),
// mirroring the resource-service layout of the AWS and GCP SDKs.
type Client struct {
	cfg        config
	httpClient *http.Client

	swa           swaapi.ClientInterface
	requestEditor RequestEditorFn

	trustDomains *TrustDomainsService
	serverGroups *ServerGroupsService
	nodeGroups   *NodeGroupsService
	servers      *ServersService
	wellKnown    *WellKnownService
}

// NewClient constructs a Client from the given options. At minimum a base URL is
// required (WithBaseURL). Authentication is configured through one of the
// WithConjurToken / WithTokenSource / WithRoundTripper options; endpoints that
// require auth will fail with 401 if none is provided.
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if strings.TrimSpace(cfg.baseURL) == "" {
		return nil, ErrMissingBaseURL
	}
	cfg.baseURL = normalizeBaseURL(cfg.baseURL)

	httpClient := buildHTTPClient(cfg)

	// Editors common to every request: identity headers.
	common := []RequestEditorFn{
		userAgentEditor(cfg.userAgent),
	}
	// Authenticated surface carries the token and the versioned Accept header.
	authedExtra := []RequestEditorFn{
		acceptEditor(cfg.mediaType),
		authEditor(cfg.authScheme, cfg.tokenSource),
	}

	swaEditors := combineEditors(append(append(slices.Clone(common), authedExtra...), cfg.editors...)...)

	swaLL, err := swaapi.NewClient(cfg.baseURL, swaapi.WithHTTPClient(httpClient), swaapi.WithRequestEditorFn(swaEditors))
	if err != nil {
		return nil, err
	}

	c := &Client{cfg: cfg, httpClient: httpClient, swa: swaLL, requestEditor: swaEditors}
	c.trustDomains = &TrustDomainsService{client: c}
	c.serverGroups = &ServerGroupsService{client: c}
	c.nodeGroups = &NodeGroupsService{client: c}
	c.servers = &ServersService{client: c}
	c.wellKnown = &WellKnownService{client: c}
	return c, nil
}

// NewManagement constructs a client for the control-plane management surface.
func NewManagement(opts ...Option) (ManagementAPI, error) {
	return NewClient(opts...)
}

// BaseURL returns the configured base URL the client connects to.
func (c *Client) BaseURL() string {
	return c.cfg.baseURL
}

// HTTPClient returns the effective HTTP client used by the SWA client.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// RequestEditor returns a RequestEditorFn that applies the client's configured
// authentication, tracing, and identity headers.
func (c *Client) RequestEditor() RequestEditorFn {
	return c.requestEditor
}

// TrustDomains returns the service for managing SWA trust domains.
func (c *Client) TrustDomains() TrustDomainsAPI { return c.trustDomains }

// ServerGroups returns the service for managing SWA server groups.
func (c *Client) ServerGroups() ServerGroupsAPI { return c.serverGroups }

// NodeGroups returns the service for managing SWA node groups.
func (c *Client) NodeGroups() NodeGroupsAPI { return c.nodeGroups }

// Servers returns the service for managing SWA servers (components).
func (c *Client) Servers() ServersAPI { return c.servers }

// WellKnown returns the service for the public discovery endpoints (CA bundles,
// JWKS, OpenID configuration).
func (c *Client) WellKnown() WellKnownAPI { return c.wellKnown }

// Livez calls the SWA liveness probe. It returns nil when the service is alive.
func (c *Client) Livez(ctx context.Context) error {
	resp, err := c.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return c.swa.GetLivez(ctx)
	})
	if err != nil {
		return err
	}
	return HandleResponse("Livez", resp, nil, []int{http.StatusOK})
}

// Execute runs a single low-level call, applying the retry policy for idempotent
// operations. The call closure must build and send the request fresh on each
// invocation (the generated clients do), so retries are safe.
func (c *Client) Execute(ctx context.Context, idempotent bool, call func(context.Context) (*http.Response, error)) (*http.Response, error) {
	attempts := 1
	if idempotent && c.cfg.retry.enabled() {
		attempts += c.cfg.retry.MaxRetries
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.cfg.retry.backoff(attempt)):
			}
		}

		resp, err := call(ctx)
		if err != nil {
			lastErr = err
			if idempotent && attempt < attempts-1 {
				continue
			}
			return nil, err
		}

		if idempotent && attempt < attempts-1 && retryableStatus(resp.StatusCode) {
			DrainClose(resp)
			lastErr = &swaerrors.APIError{Op: opRetry, StatusCode: resp.StatusCode}
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// HandleResponse reads and closes the response, decoding the body into out when
// the status is one of okStatuses, or converting it into an *swaerrors.APIError
// using ParseStandardError otherwise.
func HandleResponse(op swaerrors.Op, resp *http.Response, out any, okStatuses []int) error {
	return HandleResponseWithParser(op, resp, out, okStatuses, ParseStandardError)
}

// HandleResponseWithParser reads and closes the response, decoding the body into out
// when the status is one of okStatuses, or converting it into an *swaerrors.APIError
// using the provided parser otherwise.
func HandleResponseWithParser(op swaerrors.Op, resp *http.Response, out any, okStatuses []int, parse ErrorParser) error {
	defer DrainClose(resp)
	body, readErr := io.ReadAll(resp.Body)
	requestID := ResponseRequestID(resp)

	if slices.Contains(okStatuses, resp.StatusCode) {
		if readErr != nil {
			return &swaerrors.APIError{Op: op, StatusCode: resp.StatusCode, RequestID: requestID, Message: "reading response body: " + readErr.Error()}
		}
		if out != nil && len(body) > 0 {
			if err := json.Unmarshal(body, out); err != nil {
				return &swaerrors.APIError{Op: op, StatusCode: resp.StatusCode, RequestID: requestID, Message: "decoding response body: " + err.Error(), Body: body}
			}
		}
		return nil
	}
	return parse(op, resp.StatusCode, requestID, body)
}

// DrainClose drains and closes a response body so the underlying connection can
// be reused, then closes it.
func DrainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// ResponseRequestID extracts the request id associated with a response,
// preferring the value echoed by the server and falling back to what the client
// sent.
func ResponseRequestID(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if id := resp.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	if resp.Request != nil {
		return resp.Request.Header.Get("X-Request-Id")
	}
	return ""
}

// normalizeBaseURL trims a trailing slash and a trailing "/api" segment so that
// URLs sourced from a Conjur CLI configuration work unchanged.
func normalizeBaseURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimSuffix(url, "/api")
	return url
}

// buildHTTPClient resolves the effective *http.Client from configuration.
func buildHTTPClient(cfg config) *http.Client {
	client := cfg.httpClient
	if client == nil {
		client = &http.Client{}
	} else {
		cloned := *client
		client = &cloned
	}
	if client.Timeout == 0 && cfg.timeout > 0 {
		client.Timeout = cfg.timeout
	}
	if cfg.transport != nil {
		client.Transport = cfg.transport
	}
	if cfg.debugOut != nil {
		client.Transport = &debugTransport{base: client.Transport, out: cfg.debugOut}
	}
	return client
}

// defaultUserAgent builds a User-Agent that includes the SDK and Go versions.
func defaultUserAgent() string {
	v := Version
	if bi, ok := debug.ReadBuildInfo(); ok && bi.GoVersion != "" {
		return "swa-sdk-go/" + v + " (" + bi.GoVersion + ")"
	}
	return "swa-sdk-go/" + v
}
