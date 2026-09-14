// Package spiffe provides a conjurapi.Config.ClientCertProvider implementation
// that sources a client certificate from the SPIFFE Workload API.
package spiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// svidExpirySkew is the margin before an SVID's NotAfter at which the cached
// certificate is considered stale. Refreshing early ensures a valid SVID is
// in hand before the current one expires at the TLS layer.
const svidExpirySkew = 30 * time.Second

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

// fetchSVIDFromWorkloadAPI fetches the first X.509-SVID from the SPIFFE Workload API
// and returns it as a *tls.Certificate together with the leaf certificate's expiry time.
// The socket address is resolved from the SPIFFE_ENDPOINT_SOCKET environment variable
// (go-spiffe/v2 default behaviour).
func fetchSVIDFromWorkloadAPI(ctx context.Context) (*tls.Certificate, time.Time, error) {
	svids, err := workloadapi.FetchX509SVIDs(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fetching X.509-SVID from workload API: %w", err)
	}
	if len(svids) == 0 {
		return nil, time.Time{}, errors.New("workload API returned no SVIDs")
	}
	if len(svids[0].Certificates) == 0 {
		return nil, time.Time{}, errors.New("X.509-SVID has no certificates")
	}

	logging.ApiLog.Debugf("spiffe: selected SVID %s (expires %s)",
		svids[0].ID, svids[0].Certificates[0].NotAfter.Format(time.RFC3339))

	certPEM, keyPEM, err := svids[0].Marshal()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("marshaling X.509-SVID: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("loading X.509-SVID as TLS certificate: %w", err)
	}

	return &cert, svids[0].Certificates[0].NotAfter, nil
}

// NewProvider returns a function that supplies the workload's X.509-SVID as a
// *tls.Certificate. The SVID is fetched once from the SPIFFE Workload API (socket
// address read from SPIFFE_ENDPOINT_SOCKET) and cached until the leaf certificate
// expires; subsequent calls return the cached value without a network round-trip.
//
// Wire the returned function into conjurapi.Config.ClientCertProvider to authenticate
// a Conjur client using authn-cert in SPIFFE mode.
func NewProvider() func(context.Context) (*tls.Certificate, error) {
	p := &provider{fetch: fetchSVIDFromWorkloadAPI}
	return p.getCertificate
}
