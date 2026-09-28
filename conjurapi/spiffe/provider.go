// Package spiffe provides a conjurapi.Config.ClientCertProvider implementation
// that sources a client certificate from the SPIFFE Workload API.
package spiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

	// retryMax is the maximum number of retries for transient Workload API
	// failures (codes.Unavailable).
	retryMax = 3
)

// retryInitial is the delay before the first retry. Declared as a var so tests
// can reduce it without sleeping.
var retryInitial = 500 * time.Millisecond

// svidFetcher is the function signature for fetching X.509-SVIDs from the
// SPIFFE Workload API. The production default is workloadapi.FetchX509SVIDs;
// tests substitute a stub to drive the retry loop and SVID selection logic
// without a real Workload API.
type svidFetcher func(ctx context.Context) ([]*x509svid.SVID, error)

// errRetry is returned by classifyWorkloadAPIError when the caller should retry
// the fetch after a backoff delay.
var errRetry = errors.New("Workload API temporarily unavailable")

// provider caches an X.509-SVID fetched from the SPIFFE Workload API and re-fetches
// when the cached certificate is within svidExpirySkew of its expiry.
type provider struct {
	mu     sync.Mutex
	cached *tls.Certificate
	expiry time.Time
	fetch  func(ctx context.Context) (*tls.Certificate, time.Time, error)
}

// getCertificate returns the cached certificate, re-fetching from the Workload API
// when the cache is empty or the certificate is within svidExpirySkew of expiry.
func (p *provider) getCertificate(ctx context.Context) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

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
		return fmt.Errorf("Workload API returned PermissionDenied: " +
			"the workload may not be registered or the SPIRE agent may not trust this process")
	case codes.Unavailable:
		return errRetry
	}
	return fmt.Errorf("Workload API request failed: %w", err)
}

// fetchSVIDFromWorkloadAPI fetches an X.509-SVID from the SPIFFE Workload API
// and returns it as a *tls.Certificate together with the leaf certificate's
// expiry time.
//
// SVID selection is governed by CONJUR_SPIFFE_ID (see NewProvider for details).
// Transient codes.Unavailable responses are retried up to retryMax times with
// exponential backoff starting at retryInitial. codes.PermissionDenied is never
// retried.
//
// fetchSVIDs is called to obtain SVIDs; in production this is
// workloadapi.FetchX509SVIDs; tests may substitute a stub.
func fetchSVIDFromWorkloadAPI(ctx context.Context, fetchSVIDs svidFetcher) (*tls.Certificate, time.Time, error) {
	delay := retryInitial
	for attempt := 0; attempt <= retryMax; attempt++ {
		svids, err := fetchSVIDs(ctx)
		if err != nil {
			classified := classifyWorkloadAPIError(err)
			if classified == errRetry && attempt < retryMax {
				logging.ApiLog.Debugf("spiffe: Workload API unavailable (attempt %d/%d); retrying in %s",
					attempt+1, retryMax, delay)
				select {
				case <-ctx.Done():
					return nil, time.Time{}, ctx.Err()
				case <-time.After(delay):
				}
				delay *= 2
				continue
			}
			if classified == errRetry {
				return nil, time.Time{}, fmt.Errorf("SPIFFE Workload API still unavailable after %d retries", retryMax)
			}
			return nil, time.Time{}, classified
		}

		if len(svids) == 0 {
			return nil, time.Time{}, errors.New("Workload API returned no SVIDs")
		}

		// SVID selection: CONJUR_SPIFFE_ID names the required SPIFFE ID.
		// When unset, exactly one SVID must be present; multiple SVIDs are
		// an error — a silent default re-points the workload identity.
		wantID := os.Getenv("CONJUR_SPIFFE_ID")
		svid := svids[0]

		if wantID == "" && len(svids) > 1 {
			candidates := make([]string, len(svids))
			for i, s := range svids {
				candidates[i] = s.ID.String()
			}
			return nil, time.Time{}, fmt.Errorf(
				"Workload API returned %d SVIDs; set CONJUR_SPIFFE_ID to one of: %s",
				len(svids), strings.Join(candidates, ", "),
			)
		}

		if wantID != "" {
			parsedID, err := spiffeid.FromString(wantID)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("CONJUR_SPIFFE_ID %q is not a valid SPIFFE ID: %w", wantID, err)
			}
			found := false
			for _, s := range svids {
				if s.ID == parsedID {
					svid = s
					found = true
					break
				}
			}
			if !found {
				candidates := make([]string, len(svids))
				for i, s := range svids {
					candidates[i] = s.ID.String()
				}
				return nil, time.Time{}, fmt.Errorf(
					"CONJUR_SPIFFE_ID %q not found; available SVIDs: %s",
					wantID, strings.Join(candidates, ", "),
				)
			}
		}

		if len(svid.Certificates) == 0 {
			return nil, time.Time{}, errors.New("X.509-SVID has no certificates")
		}

		logging.ApiLog.Debugf("spiffe: selected SVID %s (expires %s)",
			svid.ID, svid.Certificates[0].NotAfter.Format(time.RFC3339))

		certPEM, keyPEM, err := svid.Marshal()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("marshaling X.509-SVID: %w", err)
		}

		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("loading X.509-SVID as TLS certificate: %w", err)
		}

		return &cert, svid.Certificates[0].NotAfter, nil
	}

	// unreachable: the loop exits via return on every path
	return nil, time.Time{}, errors.New("fetchSVIDFromWorkloadAPI: unexpected loop exit")
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
	realFetch := func(ctx context.Context) ([]*x509svid.SVID, error) {
		return workloadapi.FetchX509SVIDs(ctx)
	}
	p := &provider{
		fetch: func(ctx context.Context) (*tls.Certificate, time.Time, error) {
			return fetchSVIDFromWorkloadAPI(ctx, realFetch)
		},
	}
	return p.getCertificate
}
