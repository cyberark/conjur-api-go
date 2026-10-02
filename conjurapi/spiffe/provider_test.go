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
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestSocketPath_UnixSocket(t *testing.T) {
	tests := []struct {
		socket string
		want   string
	}{
		{"unix:///var/run/spire.sock", "/var/run/spire.sock"},
		{"unix:/var/run/spire.sock", "/var/run/spire.sock"},
		// Malformed (missing third slash): url.Parse splits into Host="var",
		// Path="/run/spire.sock". Return Host+Path so the pre-check operates
		// on the same segments that url.Parse extracted.
		{"unix://var/run/spire.sock", "var/run/spire.sock"},
		{"", ""},
		{"tcp://127.0.0.1:8888", ""},
	}
	for _, tc := range tests {
		got := socketPath(tc.socket)
		assert.Equal(t, tc.want, got, "socketPath(%q)", tc.socket)
	}
}

func TestValidateWorkloadEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		socket    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:   "empty socket passes",
			socket: "",
		},
		{
			name:   "unix socket passes",
			socket: "unix:///var/run/spire.sock",
		},
		{
			name:   "bare path passes",
			socket: "/var/run/spire.sock",
		},
		{
			name:   "loopback IPv4 passes",
			socket: "tcp://127.0.0.1:8888",
		},
		{
			name:   "loopback IPv6 passes",
			socket: "tcp://[::1]:8888",
		},
		{
			name:   "localhost passes",
			socket: "tcp://localhost:8888",
		},
		{
			name:      "non-loopback tcp is blocked",
			socket:    "tcp://192.168.1.5:8888",
			wantErr:   true,
			errSubstr: "non-loopback",
		},
		{
			name:      "unsupported http scheme is rejected",
			socket:    "http://localhost:8888",
			wantErr:   true,
			errSubstr: "unsupported scheme",
		},
		{
			name:      "unsupported file scheme is rejected",
			socket:    "file:///var/run/spire.sock",
			wantErr:   true,
			errSubstr: "unsupported scheme",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWorkloadEndpoint(tc.socket)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}

	// CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT is an undocumented override; verify
	// it still permits non-loopback TCP when set.
	t.Run("non-loopback tcp allowed via CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT", func(t *testing.T) {
		t.Setenv("CONJUR_SPIFFE_ALLOW_REMOTE_ENDPOINT", "true")
		require.NoError(t, validateWorkloadEndpoint("tcp://192.168.1.5:8888"))
	})
}

func TestClassifyWorkloadAPIError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		assert.NoError(t, classifyWorkloadAPIError(nil))
	})

	t.Run("codes.Unavailable returns errRetry sentinel", func(t *testing.T) {
		err := status.Error(codes.Unavailable, "service unavailable")
		got := classifyWorkloadAPIError(err)
		assert.Equal(t, errRetry, got)
	})

	t.Run("codes.PermissionDenied returns non-retry error naming the condition", func(t *testing.T) {
		err := status.Error(codes.PermissionDenied, "access denied")
		got := classifyWorkloadAPIError(err)
		require.Error(t, got)
		assert.NotEqual(t, errRetry, got)
		assert.Contains(t, got.Error(), "PermissionDenied")
		// Error must not leak gRPC error message that could contain sensitive context
		assert.NotContains(t, got.Error(), "access denied")
	})

	t.Run("transport error returns handshake-failure message distinct from socket-not-found", func(t *testing.T) {
		plain := errors.New("connection reset by peer")
		got := classifyWorkloadAPIError(plain)
		require.Error(t, got)
		assert.NotEqual(t, errRetry, got)
		assert.Contains(t, got.Error(), "Workload API request failed")
		assert.NotContains(t, got.Error(), "not found")
	})
}

func TestFetchSVIDFromWorkloadAPI(t *testing.T) {
	unavailErr := status.Error(codes.Unavailable, "temporarily unavailable")
	permDeniedErr := status.Error(codes.PermissionDenied, "access denied")

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

	t.Run("retries on Unavailable then succeeds", func(t *testing.T) {
		orig := retryInitial
		retryInitial = time.Millisecond
		t.Cleanup(func() { retryInitial = orig })

		svid := makeTestSVID(t, okID)
		f := stub(resp{nil, unavailErr}, resp{nil, unavailErr}, resp{[]*x509svid.SVID{svid}, nil})
		cert, expiry, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.False(t, expiry.IsZero())
	})

	t.Run("returns error after retryMax retries exhausted", func(t *testing.T) {
		orig := retryInitial
		retryInitial = time.Millisecond
		t.Cleanup(func() { retryInitial = orig })

		pairs := make([]resp, retryMax+2)
		for i := range pairs {
			pairs[i] = resp{nil, unavailErr}
		}
		f := stub(pairs...)
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "still unavailable after")
	})

	t.Run("PermissionDenied fails immediately without retry", func(t *testing.T) {
		callCount := 0
		f := func(_ context.Context) ([]*x509svid.SVID, error) {
			callCount++
			return nil, permDeniedErr
		}
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PermissionDenied")
		assert.Equal(t, 1, callCount)
	})

	t.Run("context cancellation during backoff returns context error", func(t *testing.T) {
		orig := retryInitial
		retryInitial = time.Millisecond
		t.Cleanup(func() { retryInitial = orig })

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f := func(_ context.Context) ([]*x509svid.SVID, error) {
			return nil, unavailErr
		}
		_, _, err := fetchSVIDFromWorkloadAPI(ctx, f)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

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

	t.Run("socket path not found returns actionable error", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "/tmp/no-such-spire-agent-socket-xyz.sock")
		// fetchSVIDs should never be called — the pre-check exits first.
		f := func(_ context.Context) ([]*x509svid.SVID, error) {
			t.Fatal("fetchSVIDs called despite missing socket")
			return nil, nil
		}
		_, _, err := fetchSVIDFromWorkloadAPI(context.Background(), f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "/tmp/no-such-spire-agent-socket-xyz.sock")
	})
}

func TestCheckSocketPath(t *testing.T) {
	t.Run("returns nil when socket exists", func(t *testing.T) {
		f, err := os.CreateTemp("", "spire-test-*.sock")
		require.NoError(t, err)
		f.Close()
		defer os.Remove(f.Name())

		assert.NoError(t, checkSocketPath(f.Name()))
	})

	t.Run("returns not-found error when path is absent", func(t *testing.T) {
		err := checkSocketPath("/tmp/no-such-spire-socket-xyz-test.sock")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "/tmp/no-such-spire-socket-xyz-test.sock")
	})
}

// ---------------------------------------------------------------------------
// selectBySpiffeID
// ---------------------------------------------------------------------------

func TestSelectBySpiffeID(t *testing.T) {
	id1, _ := spiffeid.FromString("spiffe://example.org/a")
	id2, _ := spiffeid.FromString("spiffe://example.org/b")

	t.Run("empty want + single SVID returns index 0", func(t *testing.T) {
		idx, err := selectBySpiffeID([]spiffeid.ID{id1}, "")
		require.NoError(t, err)
		assert.Equal(t, 0, idx)
	})

	t.Run("empty want + multiple SVIDs returns error listing candidates", func(t *testing.T) {
		_, err := selectBySpiffeID([]spiffeid.ID{id1, id2}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "set CONJUR_SPIFFE_ID")
		assert.Contains(t, err.Error(), "spiffe://example.org/a")
		assert.Contains(t, err.Error(), "spiffe://example.org/b")
	})

	t.Run("valid want that matches returns correct index", func(t *testing.T) {
		idx, err := selectBySpiffeID([]spiffeid.ID{id1, id2}, "spiffe://example.org/b")
		require.NoError(t, err)
		assert.Equal(t, 1, idx)
	})

	t.Run("invalid want format returns error", func(t *testing.T) {
		_, err := selectBySpiffeID([]spiffeid.ID{id1}, "not-a-spiffe-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid SPIFFE ID")
	})

	t.Run("valid want not found returns error listing candidates", func(t *testing.T) {
		_, err := selectBySpiffeID([]spiffeid.ID{id1}, "spiffe://example.org/missing")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "spiffe://example.org/a")
	})
}
