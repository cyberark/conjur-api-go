package authn

type TokenAuthenticator struct {
	Token string `env:"CONJUR_AUTHN_TOKEN"`
}

func (a *TokenAuthenticator) NeedsTokenRefresh() bool {
	return false
}

func (a *TokenAuthenticator) RefreshToken() ([]byte, error) {
	return []byte(a.Token), nil
}

func (a *TokenAuthenticator) Username() (string, error) {
	token, err := NewToken([]byte(a.Token))
	if err != nil {
		return "", err
	}

	return token.Username(), nil
}
