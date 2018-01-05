package conjurapi

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func (c *Client) RefreshToken() (err error) {
	var token authn.AuthnToken

	if c.NeedsTokenRefresh() {
		var tokenBytes []byte
		tokenBytes, err = c.authenticator.RefreshToken()
		if err == nil {
			token, err = authn.NewToken(tokenBytes)
			if err != nil {
				return
			}
			token.FromJSON(tokenBytes)
			c.authToken = token
		}
	}

	return
}

func (c *Client) NeedsTokenRefresh() bool {
	return c.authToken == nil ||
		c.authToken.ShouldRefresh() || 
		c.authenticator.NeedsTokenRefresh()
}

func (c *Client) createAuthRequest(req *http.Request) (error) {
	if err := c.RefreshToken(); err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString(c.authToken.Raw())),
	)

	return nil
}

func (c *Client) Authenticate(loginPair authn.LoginPair) ([]byte, error) {
	req, err := c.router.AuthenticateRequest(loginPair)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return response.SecretDataResponse(resp)
}

func (c *Client) RotateAPIKey(roleId string) ([]byte, error) {
	req, err := c.router.RotateAPIKeyRequest(roleId)
	if err != nil {
		return nil, err
	}

  resp, err := c.SubmitRequest(req)
  if err != nil {
    return nil, err
  }

	return response.SecretDataResponse(resp)
}
