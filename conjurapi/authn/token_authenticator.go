package authn

import (
  "fmt"
)

type TokenAuthenticator struct {
  Token string `env:"CONJUR_AUTHN_TOKEN"`
}

func (a *TokenAuthenticator) RefreshToken() ([]byte, error) {
  return nil, fmt.Errorf("When Conjur is constructed with a token, the token can't be refreshed")
}

func (a *TokenAuthenticator) NeedsTokenRefresh() bool {
  return false
}
