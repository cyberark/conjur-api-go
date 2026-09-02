package swa

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockAPI is a declarative test double for the SWA HTTP API. Instead of
// hand-writing an http.HandlerFunc that switches on method/path and pokes a raw
// http.ResponseWriter, tests register route -> response expectations fluently:
//
//	api := newMockAPI(t)
//	api.GET("/api/swa/trust-domains/prod").RespondJSON(http.StatusOK, td)
//	api.POST("/api/swa/trust-domains").RespondJSON(http.StatusCreated, td)
//	c := api.Client()
//
// A route can queue several responses, returned in order (the last repeats),
// which models retries and pagination without shared mutable counters:
//
//	r := api.GET(path).
//		RespondStatus(http.StatusServiceUnavailable).
//		RespondStatus(http.StatusServiceUnavailable).
//		RespondJSON(http.StatusOK, td) // recovered on the 3rd attempt
//
// Each capturedRequest records the whole response that answered it, so a test
// can inspect exactly what a particular call got back, not just the last one:
//
//	assert.Equal(t, http.StatusOK, r.Requests()[2].Response.status) // 3rd call recovered
//
// Every matched request is captured on its route, so tests assert on what the
// client actually sent (headers, query, body) after the call:
//
//	r := api.GET(path).RespondJSON(http.StatusOK, td)
//	// ... invoke the client ...
//	require.Equal(t, `Token token="test-token"`, r.LastRequest().Header.Get("Authorization"))
//
// api.Requests() returns the routes that were hit, in call order, shared across
// all routes, so tests can assert call order across routes (e.g. a GET probe
// happening before the POST/PATCH it gates), not just per-route counts:
//
//	assert.Equal(t, []*route{get, post}, api.Requests())
//
// An unmatched request fails the test, so "the server must not be called" is
// expressed simply by not registering a route.
//
// It is deliberately backed by httptest.NewServer: the full client stack —
// header injection, query encoding, retry/backoff, response parsing — is
// exercised end to end over loopback, and only the server side is faked. Use "*"
// as the path to match any path, for behaviour tests where the exact route isn't
// the point (e.g. Apply's create-vs-update decision).
type mockAPI struct {
	t        *testing.T
	mu       sync.Mutex
	routes   []*route
	requests []*route
}

func newMockAPI(t *testing.T) *mockAPI {
	t.Helper()
	return &mockAPI{t: t}
}

// Client starts the mock server (closed at test cleanup) and returns a *Client
// pointed at it, authenticated with a static Conjur token.
func (m *mockAPI) Client(opts ...Option) *Client {
	m.t.Helper()
	srv := httptest.NewServer(m)
	m.t.Cleanup(srv.Close)

	base := []Option{WithBaseURL(srv.URL), WithConjurToken("test-token")}
	c, err := NewClient(append(base, opts...)...)
	require.NoError(m.t, err)
	return c
}

// On registers a route for the given method and path ("*" matches any path).
func (m *mockAPI) On(method, path string) *route {
	r := &route{method: method, path: path}
	m.routes = append(m.routes, r)
	return r
}

func (m *mockAPI) GET(path string) *route    { return m.On(http.MethodGet, path) }
func (m *mockAPI) POST(path string) *route   { return m.On(http.MethodPost, path) }
func (m *mockAPI) PATCH(path string) *route  { return m.On(http.MethodPatch, path) }
func (m *mockAPI) DELETE(path string) *route { return m.On(http.MethodDelete, path) }

// ServeHTTP dispatches a request to the first matching route (in registration
// order) and records it. Unmatched requests fail the test.
func (m *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rt := range m.routes {
		if rt.method != r.Method || (rt.path != "*" && rt.path != r.URL.Path) {
			continue
		}
		rt.requests = append(rt.requests, &capturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
			Body:   body,
		})
		m.requests = append(m.requests, rt)
		rt.respond(m.t, w)
		return
	}

	m.t.Errorf("mockAPI: unexpected request %s %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusNotImplemented)
}

// Requests returns the routes that were hit, in call order. A route that was
// called twice appears twice, at its two positions, so tests can assert an
// exact call sequence across routes, e.g.:
//
//	assert.Equal(t, []*route{get, post}, api.Requests())
func (m *mockAPI) Requests() []*route {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*route(nil), m.requests...)
}

// respOpt customizes a queued response.
type respOpt func(*response)

// withHeader sets a response header (e.g. an echoed X-Request-Id).
func withHeader(key, val string) respOpt {
	return func(r *response) {
		if r.headers == nil {
			r.headers = map[string]string{}
		}
		r.headers[key] = val
	}
}

// response is a single queued reply for a route.
type response struct {
	status  int
	body    any // nil => empty body
	headers map[string]string
}

type route struct {
	method    string
	path      string
	responses []response
	requests  []*capturedRequest
}

// RespondJSON queues a JSON response with the given status and body.
func (r *route) RespondJSON(status int, body any, opts ...respOpt) *route {
	return r.queue(response{status: status, body: body}, opts)
}

// RespondStatus queues a bodiless response with the given status.
func (r *route) RespondStatus(status int, opts ...respOpt) *route {
	return r.queue(response{status: status}, opts)
}

func (r *route) queue(resp response, opts []respOpt) *route {
	for _, o := range opts {
		o(&resp)
	}
	r.responses = append(r.responses, resp)
	return r
}

// respond writes the response for the current call (indexed by how many requests
// this route has received; the last queued response repeats) and records which
// queued response matched onto the just-captured request.
func (r *route) respond(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	if len(r.responses) == 0 {
		t.Errorf("mockAPI: route %s %s matched but no response was configured", r.method, r.path)
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	idx := len(r.requests) - 1
	if idx >= len(r.responses) {
		idx = len(r.responses) - 1
	}
	resp := r.responses[idx]
	r.requests[len(r.requests)-1].Response = &resp

	for k, v := range resp.headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", DefaultMediaType)
	w.WriteHeader(resp.status)
	if resp.body != nil {
		require.NoError(t, json.NewEncoder(w).Encode(resp.body))
	}
}

// Count reports how many times this route was called.
func (r *route) Count() int { return len(r.requests) }

// LastRequest returns the most recent captured request, or nil if none.
func (r *route) LastRequest() *capturedRequest {
	if len(r.requests) == 0 {
		return nil
	}
	return r.requests[len(r.requests)-1]
}

// Requests returns every request this route captured, in call order. Combined
// with Response on each capturedRequest, this lets a test with a multi-response
// route (e.g. a retry-then-recover sequence) check which response a particular
// call actually received, not just the last one.
func (r *route) Requests() []*capturedRequest {
	return append([]*capturedRequest(nil), r.requests...)
}

// capturedRequest is a snapshot of a request the mock received.
type capturedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
	// Response is the queued response that answered this request. Useful when a
	// route was given several responses (e.g. a retry-then-recover sequence) and
	// a test needs to check the status/body/headers a particular call actually
	// got, not just the last one.
	Response *response
}

// DecodeBody unmarshals the captured JSON body into dst.
func (c *capturedRequest) DecodeBody(t *testing.T, dst any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(bytes.NewReader(c.Body)).Decode(dst))
}
