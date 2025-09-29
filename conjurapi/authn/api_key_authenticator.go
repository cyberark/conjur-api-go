package authn

type APIKeyAuthenticator struct {
	// Authenticate is a function that takes a LoginPair and returns a JWT token or an error.
	// It will usually be set to Client.Authenticate.
	Authenticate func(loginPair LoginPair) ([]byte, error)
	// LoginPair holds the login and API key for authentication.
	LoginPair
}

type LoginPair struct {
	Login  string
	APIKey string
}

func (a *APIKeyAuthenticator) RefreshToken() ([]byte, error) {
	// Call the Authenticate function with the stored LoginPair to get a new Conjur access token.
	return a.Authenticate(a.LoginPair)
}

func (a *APIKeyAuthenticator) NeedsTokenRefresh() bool {
	// API Key authentication does not require token refresh logic.
	// Expiration of the access token is handled by the Client (see NeedsTokenRefresh in authn.go).
	return false
}
