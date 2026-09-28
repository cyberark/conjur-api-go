package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeFakeCert generates a self-signed TLS certificate with the given NotAfter time.
func makeFakeCert(t *testing.T, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	)
	require.NoError(t, err)
	return &cert
}

func TestProvider_ReturnsCachedCertificate(t *testing.T) {
	calls := 0
	cert := makeFakeCert(t, time.Now().Add(time.Hour))
	expiry := time.Now().Add(time.Hour)

	p := &provider{
		fetch: func(_ context.Context) (*tls.Certificate, time.Time, error) {
			calls++
			return cert, expiry, nil
		},
	}

	got1, err := p.getCertificate(context.Background())
	require.NoError(t, err)

	got2, err := p.getCertificate(context.Background())
	require.NoError(t, err)

	assert.Same(t, got1, got2, "expected the same cached certificate pointer on second call")
	assert.Equal(t, 1, calls, "expected only one fetch — second call must use cache")
}

func TestProvider_RefetchesAfterExpiry(t *testing.T) {
	calls := 0
	cert := makeFakeCert(t, time.Now().Add(time.Hour))

	p := &provider{
		fetch: func(_ context.Context) (*tls.Certificate, time.Time, error) {
			calls++
			// Return a certificate that is already expired so every call invalidates
			// the cache on the next invocation.
			return cert, time.Now().Add(-time.Second), nil
		},
	}

	_, err := p.getCertificate(context.Background())
	require.NoError(t, err)

	_, err = p.getCertificate(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "expected two fetch calls — cache must be bypassed after expiry")
}

func TestProvider_RefetchesWithinExpirySkew(t *testing.T) {
	calls := 0
	cert := makeFakeCert(t, time.Now().Add(time.Hour))

	p := &provider{
		fetch: func(_ context.Context) (*tls.Certificate, time.Time, error) {
			calls++
			// Return a certificate whose expiry is inside the skew window so the
			// cache is considered stale on the very next call.
			return cert, time.Now().Add(svidExpirySkew / 2), nil
		},
	}

	_, err := p.getCertificate(context.Background())
	require.NoError(t, err)

	_, err = p.getCertificate(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "expected two fetch calls — cert within skew window must not be served from cache")
}

func TestProvider_PropagatesFetchError(t *testing.T) {
	p := &provider{
		fetch: func(_ context.Context) (*tls.Certificate, time.Time, error) {
			return nil, time.Time{}, errors.New("workload API unavailable")
		},
	}

	_, err := p.getCertificate(context.Background())
	assert.ErrorContains(t, err, "workload API unavailable")
}

func TestNewProvider_ReturnsCallableFunction(t *testing.T) {
	fn := NewProvider()
	assert.NotNil(t, fn)
}

// makeTestSVID builds a minimal *x509svid.SVID suitable for unit tests.
// The certificate is self-signed and does not carry a SPIFFE URI SAN; it is
// valid only for marshalling into a TLS key pair (no Workload API validation).
func makeTestSVID(t *testing.T, id spiffeid.ID) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{cert},
		PrivateKey:   key,
	}
}

func TestFetchSVIDFromWorkloadAPI(t *testing.T) {
	// stub builds a svidFetcher that replays the given (svids, err) pairs in order.
	stub := func(pairs ...struct {
		svids []*x509svid.SVID
		err   error
	}) svidFetcher {
		i := 0
		return func(_ context.Context) ([]*x509svid.SVID, error) {
			if i >= len(pairs) {
				return nil, errors.New("stub: no more responses")
			}
			p := pairs[i]
			i++
			return p.svids, p.err
		}
	}

	type resp = struct {
		svids []*x509svid.SVID
		err   error
	}

	okID, err := spiffeid.FromString("spiffe://example.org/workload")
	require.NoError(t, err)

	t.Run("no SVIDs returned", func(t *testing.T) {
		f := stub(resp{[]*x509svid.SVID{}, nil})
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no SVIDs")
	})

	t.Run("multiple SVIDs with no selector", func(t *testing.T) {
		id1, _ := spiffeid.FromString("spiffe://example.org/a")
		id2, _ := spiffeid.FromString("spiffe://example.org/b")
		f := stub(resp{[]*x509svid.SVID{{ID: id1}, {ID: id2}}, nil})
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "set CONJUR_SPIFFE_ID")
		assert.Contains(t, err.Error(), "spiffe://example.org/a")
	})

	t.Run("CONJUR_SPIFFE_ID invalid format", func(t *testing.T) {
		t.Setenv("CONJUR_SPIFFE_ID", "not-a-valid-spiffe-id")
		f := stub(resp{[]*x509svid.SVID{{ID: okID}}, nil})
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid SPIFFE ID")
	})

	t.Run("CONJUR_SPIFFE_ID not found among available SVIDs", func(t *testing.T) {
		t.Setenv("CONJUR_SPIFFE_ID", "spiffe://example.org/missing")
		present, _ := spiffeid.FromString("spiffe://example.org/present")
		f := stub(resp{[]*x509svid.SVID{{ID: present}}, nil})
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "spiffe://example.org/present")
	})

	t.Run("CONJUR_SPIFFE_ID case-mismatch does not silently match", func(t *testing.T) {
		// go-spiffe normalises trust-domain to lowercase; FromString on an
		// uppercase trust-domain either fails or produces the normalised form.
		// Either way, "EXAMPLE.ORG" must not silently match "example.org".
		t.Setenv("CONJUR_SPIFFE_ID", "spiffe://EXAMPLE.ORG/workload")
		normalised, _ := spiffeid.FromString("spiffe://example.org/workload")
		f := stub(resp{[]*x509svid.SVID{{ID: normalised}}, nil})
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err) // parse failure or not-found — never a silent match
	})

	t.Run("CONJUR_SPIFFE_ID selects the matching SVID", func(t *testing.T) {
		t.Setenv("CONJUR_SPIFFE_ID", "spiffe://example.org/workload")
		other, _ := spiffeid.FromString("spiffe://example.org/other")
		wantSVID := makeTestSVID(t, okID)
		f := stub(resp{[]*x509svid.SVID{{ID: other}, wantSVID}, nil})
		cert, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})
}
