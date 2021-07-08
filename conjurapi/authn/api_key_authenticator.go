package authn

type APIKeyAuthenticator struct {
	Authenticate func(loginPair LoginPair) ([]byte, error)
	LoginPair
}

type LoginPair struct {
	Login  string
	APIKey string
}

func (a *APIKeyAuthenticator) NeedsTokenRefresh() bool {
	return false
}

func (a *APIKeyAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate(a.LoginPair)
}

func (a *APIKeyAuthenticator) Username() (string, error) {
	return a.LoginPair.Login, nil
}
