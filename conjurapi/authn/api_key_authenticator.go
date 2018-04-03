package authn

import "time"

var TOKEN_STALE = 4 * time.Minute

type APIKeyAuthenticator struct {
	Authenticate func(loginPair LoginPair) ([]byte, error)
	LoginPair
	tokenBorn time.Time
}

type LoginPair struct {
	Login  string
	APIKey string
}

func (a *APIKeyAuthenticator) RefreshToken() ([]byte, error) {
	tokenBytes, err := a.Authenticate(a.LoginPair)
	if err == nil {
		a.tokenBorn = time.Now()
	}
	return tokenBytes, err
}

func (a *APIKeyAuthenticator) NeedsTokenRefresh() bool {
	return time.Now().Sub(a.tokenBorn) > TOKEN_STALE
}
