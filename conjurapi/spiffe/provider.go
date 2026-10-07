// Package spiffe provides conjurapi.Config.ClientCertProvider and
// conjurapi.Config.JWTProvider implementations that source credentials from
// the SPIFFE Workload API (SPIRE agent).
package spiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// svidExpirySkew is the margin before an SVID's NotAfter at which the cached
	// certificate is considered stale. Refreshing early ensures a valid SVID is
	// in hand before the current one expires at the TLS layer.
	svidExpirySkew = 30 * time.Second

	// jwtExpirySkew is the margin before a JWT-SVID's expiry at which the cached
	// token is considered stale. Refreshing early avoids presenting an expired
	// token to Conjur when the Workload API round-trip takes non-trivial time.
	jwtExpirySkew = 30 * time.Second

	// retryMax is the maximum number of retries for transient Workload API
	// failures (codes.Unavailable).
	retryMax = 3

	// envSpiffeEndpointSocket is the standard SPIFFE env var that names the
	// Workload API socket address (unix:///path or tcp://host:port).
	envSpiffeEndpointSocket = "SPIFFE_ENDPOINT_SOCKET"

	// envConjurSpiffeID selects a specific SVID by SPIFFE ID when the Workload
	// API returns multiple SVIDs for this workload.
	envConjurSpiffeID = "CONJUR_SPIFFE_ID"

	// envConjurSpiffeAllowRemoteEndpoint is an undocumented override that
	// permits non-loopback tcp: addresses. Most deployments must not set this.
	envConjurSpiffeAllowRemoteEndpoint = "CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT"
)

// retryInitial is the delay before the first retry. Declared as a var so tests
// can reduce it without sleeping.
var retryInitial = 500 * time.Millisecond

// svidFetcher is the function signature for fetching X.509-SVIDs from the
// SPIFFE Workload API. The production default is workloadapi.FetchX509SVIDs;
// tests substitute a stub to drive the retry loop without a real Workload API.
type svidFetcher func(ctx context.Context) ([]*x509svid.SVID, error)

// jwtSVIDFetcher is the function signature for fetching JWT-SVIDs from the
// SPIFFE Workload API. The production default wraps workloadapi.FetchJWTSVIDs;
// tests substitute a stub.
type jwtSVIDFetcher func(ctx context.Context, audience string) ([]*jwtsvid.SVID, error)

// errRetry is returned by classifyWorkloadAPIError when the caller should retry
// the fetch after a backoff delay.
var errRetry = errors.New("Workload API temporarily unavailable")

// provider caches an X.509-SVID fetched from the SPIFFE Workload API and re-fetches
// when the cached certificate is within svidExpirySkew of its expiry.
type provider struct {
	mu     sync.Mutex                                                     // serialises cache reads and writes
	cached *tls.Certificate                                               // nil until the first successful fetch
	expiry time.Time                                                      // NotAfter of the leaf certificate in cached
	fetch  func(ctx context.Context) (*tls.Certificate, time.Time, error) // production: fetchSVIDFromWorkloadAPI
}

// getCertificate returns the cached certificate, re-fetching from the Workload API
// when the cache is empty or the certificate is within svidExpirySkew of expiry.
func (p *provider) getCertificate(ctx context.Context) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Return the cached cert if it exists and is more than svidExpirySkew away
	// from expiry. The skew gives the TLS handshake time to complete before the
	// cert expires at the server.
	if p.cached != nil && time.Now().Before(p.expiry.Add(-svidExpirySkew)) {
		return p.cached, nil
	}

	cert, expiry, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	p.cached = cert
	p.expiry = expiry
	return p.cached, nil
}

// jwtProvider caches a JWT-SVID token string fetched from the SPIFFE Workload
// API and re-fetches when the cached token is within jwtExpirySkew of expiry.
type jwtProvider struct {
	mu     sync.Mutex // serialises cache reads and writes
	cached string     // empty until the first successful fetch
	expiry time.Time  // expiry reported by the JWT-SVID
	fetch  func(ctx context.Context) (string, time.Time, error)
}

// getJWT returns the cached JWT string, re-fetching from the Workload API when
// the cache is empty or the token is within jwtExpirySkew of expiry.
func (p *jwtProvider) getJWT(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != "" && time.Now().Before(p.expiry.Add(-jwtExpirySkew)) {
		return p.cached, nil
	}

	token, expiry, err := p.fetch(ctx)
	if err != nil {
		return "", err
	}
	p.cached = token
	p.expiry = expiry
	return p.cached, nil
}

// validateWorkloadEndpoint checks that SPIFFE_ENDPOINT_SOCKET is acceptable.
// Unix sockets and bare paths are always allowed. TCP is restricted to loopback
// addresses (127.0.0.1, ::1, localhost) because the Workload API uses insecure
// gRPC credentials and X.509-SVID responses contain the private key. Any
// unsupported scheme (e.g. http:, file:) is rejected with an actionable error.
// Non-loopback TCP can be enabled by setting CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT=true.
func validateWorkloadEndpoint(socket string) error {
	if socket == "" {
		return nil
	}
	u, err := url.Parse(socket)
	if err != nil {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET %q is not a valid URL: %w", socket, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "unix", "":
		// Unix socket or bare path — always allowed.
		return nil
	case "tcp":
		// TCP — allowed only for loopback addresses to protect the private key
		// in transit (the Workload API uses insecure gRPC credentials).
		host := u.Hostname()
		ip := net.ParseIP(host)
		if (ip != nil && ip.IsLoopback()) || strings.EqualFold(host, "localhost") {
			return nil
		}
		// CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT is an undocumented override for
		// non-standard deployments where the SPIRE agent runs on a separate host.
		if strings.EqualFold(os.Getenv(envConjurSpiffeAllowRemoteEndpoint), "true") {
			return nil
		}
		return fmt.Errorf(
			"SPIFFE_ENDPOINT_SOCKET uses a non-loopback tcp: address (%s): "+
				"the Workload API uses insecure gRPC credentials and X.509-SVID responses contain the private key",
			socket,
		)
	default:
		return fmt.Errorf(
			"SPIFFE_ENDPOINT_SOCKET has unsupported scheme %q: use unix:/// for a socket path or tcp:// for loopback TCP",
			u.Scheme,
		)
	}
}

// socketPath extracts the file-system path from a SPIFFE_ENDPOINT_SOCKET value.
// Returns an empty string for tcp: addresses or unparseable values.
func socketPath(socket string) string {
	if socket == "" {
		return ""
	}
	u, err := url.Parse(socket)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "unix":
		// url.Parse stores the path in u.Path and any authority in u.Host.
		// Concatenating them reconstructs the file-system path for all valid
		// forms (unix:///abs/path, unix:/abs/path) without silently dropping
		// the authority segment when both components are non-empty.
		return u.Host + u.Path
	case "":
		// No scheme: treat the raw value as a file-system path.
		return socket
	}
	// tcp: or any other scheme: not a socket path.
	return ""
}

// classifyWorkloadAPIError maps an error from workloadapi.FetchX509SVIDs to one
// of the four error taxonomy cases.
//
// Case 1 (socket not found) is handled by the pre-check in fetchSVIDFromWorkloadAPI
// before the API call; this function covers cases 2–4:
//
//   - codes.PermissionDenied → fail immediately, message names the condition.
//   - codes.Unavailable      → return errRetry; caller retries with backoff.
//   - anything else          → gRPC handshake or transport failure, textually
//     distinct from "socket not found".
func classifyWorkloadAPIError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.PermissionDenied:
		// The SPIRE agent is reachable but refuses to issue an SVID for this
		// workload. Retrying will not help. The registration or selector must
		// be fixed by an operator.
		return fmt.Errorf("Workload API returned PermissionDenied: " +
			"the workload may not be registered or the SPIRE agent may not trust this process")
	case codes.Unavailable:
		// The SPIRE agent is temporarily unreachable (e.g. still starting up).
		// Signal the caller to back off and retry.
		return errRetry
	}
	// Any other gRPC status (or a transport error before a status is set)
	// is treated as a non-retryable handshake or protocol failure.
	return fmt.Errorf("Workload API request failed: %w", err)
}

// selectBySpiffeID picks the index of the matching SVID from a slice of
// SPIFFE IDs, applying the CONJUR_SPIFFE_ID selection rule.
//
// When want is empty and ids has exactly one element, index 0 is returned.
// When want is empty and ids has more than one element, an error listing all
// candidates is returned so the caller can set CONJUR_SPIFFE_ID.
// When want is set, the index of the matching ID is returned; an invalid want
// value or a missing match are errors.
func selectBySpiffeID(ids []spiffeid.ID, want string) (int, error) {
	if want == "" {
		if len(ids) > 1 {
			candidates := make([]string, len(ids))
			for i, id := range ids {
				candidates[i] = id.String()
			}
			return -1, fmt.Errorf(
				"Workload API returned %d SVIDs; set CONJUR_SPIFFE_ID to one of: %s",
				len(ids), strings.Join(candidates, ", "),
			)
		}
		return 0, nil
	}

	parsedID, err := spiffeid.FromString(want)
	if err != nil {
		return -1, fmt.Errorf("CONJUR_SPIFFE_ID %q is not a valid SPIFFE ID: %w", want, err)
	}
	for i, id := range ids {
		if id == parsedID {
			return i, nil
		}
	}
	candidates := make([]string, len(ids))
	for i, id := range ids {
		candidates[i] = id.String()
	}
	return -1, fmt.Errorf(
		"CONJUR_SPIFFE_ID %q not found; available SVIDs: %s",
		want, strings.Join(candidates, ", "),
	)
}

// selectSVID picks the correct X.509-SVID from the slice returned by the
// Workload API using the CONJUR_SPIFFE_ID selection rule.
func selectSVID(svids []*x509svid.SVID) (*x509svid.SVID, error) {
	if len(svids) == 0 {
		return nil, errors.New("Workload API returned no SVIDs")
	}
	ids := make([]spiffeid.ID, len(svids))
	for i, s := range svids {
		ids[i] = s.ID
	}
	idx, err := selectBySpiffeID(ids, os.Getenv(envConjurSpiffeID))
	if err != nil {
		return nil, err
	}
	return svids[idx], nil
}

// selectJWTSVID picks the correct JWT-SVID from the slice returned by the
// Workload API using the same CONJUR_SPIFFE_ID selection rule as selectSVID.
func selectJWTSVID(svids []*jwtsvid.SVID) (*jwtsvid.SVID, error) {
	if len(svids) == 0 {
		return nil, errors.New("Workload API returned no JWT-SVIDs")
	}
	ids := make([]spiffeid.ID, len(svids))
	for i, s := range svids {
		ids[i] = s.ID
	}
	idx, err := selectBySpiffeID(ids, os.Getenv(envConjurSpiffeID))
	if err != nil {
		return nil, err
	}
	return svids[idx], nil
}

// buildTLSCert marshals an x509svid.SVID into a *tls.Certificate and returns
// it alongside the leaf certificate's expiry time.
func buildTLSCert(svid *x509svid.SVID) (*tls.Certificate, time.Time, error) {
	if len(svid.Certificates) == 0 {
		return nil, time.Time{}, errors.New("X.509-SVID has no certificates")
	}
	logging.ApiLog.Debugf("spiffe: selected SVID %s (expires %s)",
		svid.ID, svid.Certificates[0].NotAfter.Format(time.RFC3339))

	// Marshal produces two PEM blocks: certPEM contains the certificate chain
	// (leaf first), and keyPEM contains the private key. Both are needed to
	// construct a tls.Certificate that can be presented in a TLS handshake.
	certPEM, keyPEM, err := svid.Marshal()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("marshaling X.509-SVID: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("loading X.509-SVID as TLS certificate: %w", err)
	}
	// Return the leaf certificate's NotAfter so the caller can schedule a refresh.
	return &cert, svid.Certificates[0].NotAfter, nil
}

// checkSocketPath verifies that the UNIX socket at path p exists and is
// accessible. It is called before the gRPC dial so the error message names the
// missing path rather than surfacing a generic connection-refused message.
func checkSocketPath(p string) error {
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(
				"SPIFFE_ENDPOINT_SOCKET %q not found: ensure the SPIRE agent socket is available at that path", p)
		}
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET %q is not accessible: %w", p, err)
	}
	return nil
}

// validateSocket checks that socket is an acceptable SPIFFE Workload API
// endpoint and, for unix sockets, that the path exists on disk.
func validateSocket(socket string) error {
	if err := validateWorkloadEndpoint(socket); err != nil {
		return err
	}
	// Pre-check: verify the socket path before dialing so the error message
	// names the missing path rather than producing a generic handshake failure.
	if p := socketPath(socket); p != "" {
		return checkSocketPath(p)
	}
	return nil
}

// fetchSVIDsWithRetry calls fetchSVIDs, retrying on codes.Unavailable up to
// retryMax times with exponential backoff. It returns the raw SVID list on
// success; the caller selects the right SVID and builds the certificate.
func fetchSVIDsWithRetry(ctx context.Context, fetchSVIDs svidFetcher) ([]*x509svid.SVID, error) {
	// Retry loop: attempt 0 is the first try; attempts 1..retryMax are retries.
	// Only codes.Unavailable (errRetry) triggers a retry. All other errors,
	// including codes.PermissionDenied, exit immediately.
	delay := retryInitial
	for attempt := 0; attempt <= retryMax; attempt++ {
		svids, err := fetchSVIDs(ctx)
		if err == nil {
			return svids, nil
		}

		// Classify the failure and decide whether to retry.
		classified := classifyWorkloadAPIError(err)
		if classified != errRetry {
			return nil, classified
		}
		if attempt >= retryMax {
			return nil, fmt.Errorf("SPIFFE Workload API still unavailable after %d retries", retryMax)
		}

		// Back off before the next attempt. The delay doubles on each
		// iteration (500 ms → 1 s → 2 s for the default retryMax of 3).
		logging.ApiLog.Debugf("spiffe: Workload API unavailable (attempt %d/%d); retrying in %s",
			attempt+1, retryMax, delay)
		select {
		case <-ctx.Done():
			// Propagate context cancellation immediately instead of sleeping.
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}

	// unreachable: the loop exits via return on every path
	return nil, errors.New("fetchSVIDsWithRetry: unexpected loop exit")
}

// fetchSVIDFromWorkloadAPI fetches an X.509-SVID from the SPIFFE Workload API
// and returns it as a *tls.Certificate together with the leaf certificate's
// expiry time. It proceeds in four steps:
//
//  1. validateSocket — check endpoint scheme and socket existence.
//  2. fetchSVIDsWithRetry — fetch SVIDs, retrying on transient failures.
//  3. selectSVID — choose the right SVID (by CONJUR_SPIFFE_ID or sole result).
//  4. buildTLSCert — marshal the SVID into a *tls.Certificate.
//
// fetchSVIDs is called to obtain SVIDs; in production this is
// workloadapi.FetchX509SVIDs; tests may substitute a stub.
func fetchSVIDFromWorkloadAPI(ctx context.Context, fetchSVIDs svidFetcher) (*tls.Certificate, time.Time, error) {
	// Read once so validateSocket and socketPath operate on the same value;
	// a concurrent t.Setenv in tests cannot produce inconsistency.
	socket := os.Getenv(envSpiffeEndpointSocket)
	if err := validateSocket(socket); err != nil {
		return nil, time.Time{}, err
	}
	svids, err := fetchSVIDsWithRetry(ctx, fetchSVIDs)
	if err != nil {
		return nil, time.Time{}, err
	}
	svid, err := selectSVID(svids)
	if err != nil {
		return nil, time.Time{}, err
	}
	return buildTLSCert(svid)
}

// NewProvider returns a function that supplies the workload's X.509-SVID as a
// *tls.Certificate. The SVID is fetched from the SPIFFE Workload API (socket
// address from SPIFFE_ENDPOINT_SOCKET) using the following selection rules:
//
//   - If CONJUR_SPIFFE_ID is set, the SVID whose SPIFFE ID matches it is used;
//     if no SVID matches, the call fails listing the available IDs.
//   - If CONJUR_SPIFFE_ID is unset and the Workload API returns exactly one
//     SVID, that SVID is used.
//   - If CONJUR_SPIFFE_ID is unset and multiple SVIDs are returned, the call
//     fails listing the candidates so the caller can set CONJUR_SPIFFE_ID.
//
// The certificate is cached until svidExpirySkew before its NotAfter; subsequent
// calls within that window return the cached value without a network round-trip.
//
// Wire the returned function into conjurapi.Config.ClientCertProvider to
// authenticate a Conjur client using authn-cert in SPIFFE mode.
func NewProvider() func(context.Context) (*tls.Certificate, error) {
	// Wrap workloadapi.FetchX509SVIDs in the svidFetcher signature so it can be
	// swapped out by tests without changing the fetchSVIDFromWorkloadAPI call site.
	realFetch := func(ctx context.Context) ([]*x509svid.SVID, error) {
		return workloadapi.FetchX509SVIDs(ctx)
	}
	p := &provider{
		fetch: func(ctx context.Context) (*tls.Certificate, time.Time, error) {
			return fetchSVIDFromWorkloadAPI(ctx, realFetch)
		},
	}
	// Return the bound method so each call shares the same cache.
	return p.getCertificate
}

// fetchJWTSVIDFromWorkloadAPI fetches a JWT-SVID for the given audience from the
// SPIFFE Workload API and returns the raw JWT string and its expiry time.
//
// Endpoint validation, SVID selection, and the same error taxonomy and retry
// policy as fetchSVIDFromWorkloadAPI apply.
//
// fetchSVIDs is called to obtain SVIDs; in production this wraps
// workloadapi.FetchJWTSVIDs; tests may substitute a stub.
func fetchJWTSVIDFromWorkloadAPI(ctx context.Context, audience string, fetchSVIDs jwtSVIDFetcher) (string, time.Time, error) {
	socket := os.Getenv(envSpiffeEndpointSocket)
	if err := validateWorkloadEndpoint(socket); err != nil {
		return "", time.Time{}, err
	}
	if p := socketPath(socket); p != "" {
		if err := checkSocketPath(p); err != nil {
			return "", time.Time{}, err
		}
	}

	delay := retryInitial
	for attempt := 0; attempt <= retryMax; attempt++ {
		svids, err := fetchSVIDs(ctx, audience)

		if err == nil {
			svid, err := selectJWTSVID(svids)
			if err != nil {
				return "", time.Time{}, err
			}
			logging.ApiLog.Debugf("spiffe: selected JWT-SVID %s (expires %s)",
				svid.ID, svid.Expiry.Format(time.RFC3339))
			return svid.Marshal(), svid.Expiry, nil
		}

		classified := classifyWorkloadAPIError(err)
		if classified != errRetry {
			return "", time.Time{}, classified
		}
		if attempt >= retryMax {
			return "", time.Time{}, fmt.Errorf("SPIFFE Workload API still unavailable after %d retries", retryMax)
		}
		logging.ApiLog.Debugf("spiffe: Workload API unavailable (attempt %d/%d); retrying in %s",
			attempt+1, retryMax, delay)
		select {
		case <-ctx.Done():
			return "", time.Time{}, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return "", time.Time{}, errors.New("fetchJWTSVIDFromWorkloadAPI: unexpected loop exit")
}

// NewJWTProvider returns a function that supplies a JWT-SVID token string for
// authn-jwt authentication. The SVID is fetched from the SPIFFE Workload API
// (socket address from SPIFFE_ENDPOINT_SOCKET) for the audience read from
// CONJUR_JWT_AUDIENCE at construction time (default "conjur"), using the
// following selection rules:
//
//   - If CONJUR_SPIFFE_ID is set, the SVID whose SPIFFE ID matches it is used;
//     if no SVID matches, the call fails listing the available IDs.
//   - If CONJUR_SPIFFE_ID is unset and the Workload API returns exactly one
//     SVID, that SVID is used.
//   - If CONJUR_SPIFFE_ID is unset and multiple SVIDs are returned, the call
//     fails listing the candidates so the caller can set CONJUR_SPIFFE_ID.
//
// The token is cached until jwtExpirySkew before its expiry; subsequent calls
// within that window return the cached value without a network round-trip.
//
// Assign the returned function to conjurapi.Config.JWTProvider to authenticate
// a Conjur client using authn-jwt with a SPIFFE-issued JWT-SVID. When
// SPIFFE_ENDPOINT_SOCKET and CONJUR_AUTHN_JWT_SERVICE_ID are set and no static
// token or file path is configured, conjurapi.LoadFromEnvironment auto-wires
// this provider (FR-AUTH-SPIFFE-05).
func NewJWTProvider() func(context.Context) (string, error) {
	audience := os.Getenv("CONJUR_JWT_AUDIENCE")
	if audience == "" {
		audience = "conjur"
	}
	realFetch := func(ctx context.Context, aud string) ([]*jwtsvid.SVID, error) {
		return workloadapi.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: aud})
	}
	p := &jwtProvider{
		fetch: func(ctx context.Context) (string, time.Time, error) {
			return fetchJWTSVIDFromWorkloadAPI(ctx, audience, realFetch)
		},
	}
	return p.getJWT
}
