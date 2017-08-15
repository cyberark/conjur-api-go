package conjurapi

import (
	"net/http"
	"time"
	"fmt"
)

type Authenticator interface {
	RefreshToken() ([]byte, error)
	NeedsTokenRefresh() bool
}

type client struct {
	config     Config
	authToken  *AuthnToken
	httpclient *http.Client
	authenticator Authenticator
}

func AuthnURL(ApplianceURL, Account string) string {
	return fmt.Sprintf("%s/authn/%s/%s/authenticate", ApplianceURL, Account, "%s")
}

func NewClientFromKey(config Config, Login string, APIKey string) (*client, error) {
	return newClientWithAuthenticator(
		config,
		&APIKeyAuthenticator{
			AuthnURLTemplate: AuthnURL(config.ApplianceURL, config.Account),
			Login: Login,
			APIKey: APIKey,
		},
	)
}

func NewClientFromTokenFile(config Config, TokenFile string) (*client, error) {
	return newClientWithAuthenticator(
		config,
		&TokenFileAuthenticator{
			TokenFile: TokenFile,
		},
	)
}

func newClientWithAuthenticator(config Config, authenticator Authenticator) (*client, error) {
	var (
		err error
	)

	err = config.validate()

	if err != nil {
		return nil, err
	}

	return &client{
		config:     config,
		authenticator:  authenticator,
		httpclient: &http.Client{
			Timeout: time.Second * 10,
		},
	}, nil
}

