package authn

// TokenAuthenticator handles authentication to Conjur where a Conjur access token is provided directly.
type TokenAuthenticator struct {
	Token string `env:"CONJUR_AUTHN_TOKEN"`
}

// RefreshToken returns the provided Conjur access token.
func (a *TokenAuthenticator) RefreshToken() ([]byte, error) {
	return []byte(a.Token), nil
}

func (a *TokenAuthenticator) NeedsTokenRefresh() bool {
	return false
}
