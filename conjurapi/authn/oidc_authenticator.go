package authn

import (
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type OIDCAuthenticator struct {
	AuthenticateURL string `env:"CONJUR_AUTHN_OIDC_URL"`
	IDToken         string `env:"CONJUR_AUTHN_OIDC_ID_TOKEN"`
}

func (a *OIDCAuthenticator) RefreshToken() ([]byte, error) {
	v := url.Values{}
	v.Set("id_token", a.IDToken)

	resp, err := http.PostForm(a.AuthenticateURL, v)

	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (a *OIDCAuthenticator) NeedsTokenRefresh() bool {
	// We're not going to implement a refresh token flow...
	return false
}
