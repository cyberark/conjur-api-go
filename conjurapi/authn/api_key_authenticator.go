package authn

import "time"

// The four minutes is to work around a bug in Conjur < 4.7 causing a 404 on
// long-running operations (when the token is used right around the 5 minute mark).
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
	return time.Now().Sub(a.tokenBorn) >= TOKEN_STALE
}
