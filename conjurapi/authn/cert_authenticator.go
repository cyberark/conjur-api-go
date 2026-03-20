// Package authn provides authenticator implementations for the Conjur API client.
package authn

// CertAuthenticator handles authentication to Conjur using the authn-cert authenticator.
// The client certificate and private key are embedded in the HTTP transport (mTLS); this
// struct is responsible only for invoking the authenticate endpoint.
type CertAuthenticator struct {
	// HostID is the Conjur host path (e.g. "host/vm-workloads/vm-01").
	// Leave empty for SPIFFE mode — the host is derived from the cert's SPIFFE SAN URI.
	HostID string
	// Authenticate POSTs to the authn-cert endpoint and returns a Conjur access token.
	// It is set to Client.CertAuthenticate after client construction.
	Authenticate func(hostID string) ([]byte, error)
}

// RefreshToken obtains a new Conjur access token via the authn-cert endpoint.
func (a *CertAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate(a.HostID)
}

// NeedsTokenRefresh always returns false; token expiry is managed by the Client.
func (a *CertAuthenticator) NeedsTokenRefresh() bool {
	return false
}
