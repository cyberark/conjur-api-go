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
)

const (
	// svidExpirySkew is the margin before an SVID's NotAfter at which the cached
	// certificate is considered stale. Refreshing early ensures a valid SVID is
	// in hand before the current one expires at the TLS layer.
	svidExpirySkew = 30 * time.Second
)

// svidFetcher is the function signature for fetching X.509-SVIDs from the
// SPIFFE Workload API. The production default is workloadapi.FetchX509SVIDs;
// tests substitute a stub to drive the SVID selection logic without a real
// Workload API.
type svidFetcher func(ctx context.Context) ([]*x509svid.SVID, error)

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

// fetchSVIDFromWorkloadAPI fetches an X.509-SVID from the SPIFFE Workload API
// and returns it as a *tls.Certificate together with the leaf certificate's
// expiry time.
//
// SVID selection is governed by CONJUR_SPIFFE_ID:
//   - If set, the SVID whose SPIFFE ID matches it is used; an invalid format
//     fails fast; a case-mismatched trust domain does not silently match.
//   - If unset and exactly one SVID is present, that SVID is used.
//   - If unset and multiple SVIDs are returned, the call fails listing the
//     candidates so the caller can set CONJUR_SPIFFE_ID.
//
// fetchSVIDs is called to obtain SVIDs; in production this is
// workloadapi.FetchX509SVIDs; tests may substitute a stub.
func fetchSVIDFromWorkloadAPI(ctx context.Context, fetchSVIDs svidFetcher) (*tls.Certificate, time.Time, error) {
	svids, err := fetchSVIDs(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fetching X.509-SVID from workload API: %w", err)
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
