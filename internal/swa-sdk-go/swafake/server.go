package swafake

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v4"

	swa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake/internal/serverapi/swa"
)

// Fake is the behaviour a swafake server exposes to tests. Depending on this
// interface (rather than *Server) keeps consumer test helpers swappable.
type Fake interface {
	// URL is the base URL the fake is listening on.
	URL() string
	// Client returns a *swa.Client wired to the fake.
	Client(opts ...swa.Option) *swa.Client
	// Requests returns a copy of every request the fake has received, in order.
	Requests() []CapturedRequest
	// Reset clears captured requests and all stored state.
	Reset()
	// Close shuts the fake down. Safe to call more than once.
	Close()
}

// CapturedRequest is a snapshot of a request the fake received.
type CapturedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// DecodeBody unmarshals the captured JSON body into dst.
func (c CapturedRequest) DecodeBody(v any) error {
	return json.Unmarshal(c.Body, v)
}

// Server is an in-process fake of the SWA API. Construct it with
// New and always Close it (New(t) registers cleanup automatically).
type Server struct {
	ts    *httptest.Server
	store *store

	mu       sync.Mutex
	requests []CapturedRequest
	faults   []fault

	// seeds populate initial store state; they run after the listener is up so
	// they can use the fake's base URL (e.g. for discovery endpoints).
	seeds []func(base string)

	requireAuth bool
	token       string
}

// compile-time guard: handler satisfies the generated SWA surface.
var _ swaapi.ServerInterface = (*handler)(nil)

// New starts a fake SWA server and returns it. Options seed state and tune
// behaviour. The caller must Close the returned server; prefer NewTB in tests,
// which registers cleanup automatically.
func New(opts ...Option) *Server {
	s := &Server{
		store:       newStore(),
		requireAuth: true,
	}
	for _, opt := range opts {
		opt(s)
	}

	h := &handler{srv: s}
	router := echo.New()
	swaapi.RegisterHandlers(router, h)

	s.ts = httptest.NewServer(s.middleware(router))
	for _, seed := range s.seeds {
		seed(s.ts.URL)
	}
	return s
}

// NewTB is New plus automatic t.Cleanup(Close). Use it from tests.
func NewTB(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	s := New(opts...)
	tb.Cleanup(s.Close)
	return s
}

// URL returns the base URL the fake is listening on.
func (s *Server) URL() string { return s.ts.URL }

// Close shuts the fake down. Safe to call more than once.
func (s *Server) Close() {
	if s.ts != nil {
		s.ts.Close()
	}
}

// Client returns a *swa.Client pointed at the fake, authenticated with a static
// Conjur token. Extra options are appended (and may override the defaults).
func (s *Server) Client(opts ...swa.Option) *swa.Client {
	base := []swa.Option{swa.WithBaseURL(s.ts.URL), swa.WithConjurToken("swafake-token")}
	c, err := swa.NewClient(append(base, opts...)...)
	if err != nil {
		// New with a valid base URL and token cannot fail; panic keeps the test
		// helper ergonomic (no error return on the happy path).
		panic("swafake: constructing client: " + err.Error())
	}
	return c
}

// Requests returns a copy of every request the fake has received, in order.
func (s *Server) Requests() []CapturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CapturedRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// Reset clears captured requests and all stored state (faults and auth settings
// are preserved).
func (s *Server) Reset() {
	s.mu.Lock()
	s.requests = nil
	s.mu.Unlock()
	s.store.reset()
}

// middleware records each request, applies fault injection, and enforces auth
// before delegating to the generated routing mux.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		s.mu.Lock()
		s.requests = append(s.requests, CapturedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
			Body:   body,
		})
		faults := append([]fault(nil), s.faults...)
		s.mu.Unlock()

		for _, f := range faults {
			if f.matches(r) {
				writeError(w, r, f.status, f.code, f.message)
				return
			}
		}

		if s.requireAuth && needsAuth(r.URL.Path) && r.Header.Get("Authorization") == "" {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing Authorization header")
			return
		}
		if s.token != "" && needsAuth(r.URL.Path) && !strings.Contains(r.Header.Get("Authorization"), s.token) {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Apply applies options to an already-running server. Seed callbacks fire
// immediately with the server's current base URL, the same way they do during
// New. This allows tests to reconfigure the fake after it has started.
//
// Note: options passed to Apply are not added to the permanent seed list. They
// fire once and are discarded, so Reset() will not re-apply them. This is
// intentional: Apply is for one-shot in-test mutations, not durable configuration.
func (s *Server) Apply(opts ...Option) {
	// Swap in a fresh seed slice so we can identify and run only the newly
	// added seeds, then restore the original slice.
	prev := s.seeds
	s.seeds = nil
	for _, opt := range opts {
		opt(s)
	}
	for _, seed := range s.seeds {
		seed(s.ts.URL)
	}
	s.seeds = prev
}

// needsAuth reports whether a path is on an authenticated surface. Public
// discovery (well-known) endpoints are exempt.
func needsAuth(path string) bool {
	if strings.Contains(path, "/.well-known/") {
		return false
	}
	return strings.HasPrefix(path, "/api/swa")
}
