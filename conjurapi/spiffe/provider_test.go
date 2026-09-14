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
