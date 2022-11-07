package conjurapi

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func (c *Client) RefreshToken() (err error) {
	var token *authn.AuthnToken

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

func (c *Client) createAuthRequest(req *http.Request) error {
	if err := c.RefreshToken(); err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Token token=\"%s\"", base64.StdEncoding.EncodeToString(c.authToken.Raw())),
	)

	return nil
}

// Login obtains an API key.
func (c *Client) Login(loginPair authn.LoginPair) ([]byte, error) {
	req, err := c.LoginRequest(loginPair)
	if err != nil {
		return nil, err
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(res)
}

// Authenticate obtains a new access token using the internal authenticator.
func (c *Client) InternalAuthenticate() ([]byte, error) {
	if c.authenticator == nil {
		return nil, fmt.Errorf("%s", "unable to authenticate using client without authenticator")
	}

	return c.authenticator.RefreshToken()
}

// WhoAmI obtains information on the current user.
func (c *Client) WhoAmI() ([]byte, error) {
	req, err := c.WhoAmIRequest()
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(res)
}

// Authenticate obtains a new access token.
func (c *Client) Authenticate(loginPair authn.LoginPair) ([]byte, error) {
	resp, err := c.authenticate(loginPair)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// AuthenticateReader obtains a new access token and returns it as a data stream.
func (c *Client) AuthenticateReader(loginPair authn.LoginPair) (io.ReadCloser, error) {
	resp, err := c.authenticate(loginPair)
	if err != nil {
		return nil, err
	}

	return response.SecretDataResponse(resp)
}

func (c *Client) authenticate(loginPair authn.LoginPair) (*http.Response, error) {
	req, err := c.AuthenticateRequest(loginPair)
	if err != nil {
		return nil, err
	}

	return c.httpClient.Do(req)
}

// RotateAPIKey replaces the API key of a role on the server with a new
// random secret.
//
// The authenticated user must have update privilege on the role.
func (c *Client) RotateAPIKey(roleID string) ([]byte, error) {
	resp, err := c.rotateAPIKey(roleID)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// RotateUserAPIKey constructs a role ID from a given user ID then replaces the
// API key of the role with a new random secret.
//
// The authenticated user must have update privilege on the role.
func (c *Client) RotateUserAPIKey(userID string) ([]byte, error) {
	config := c.GetConfig()
	roleID := fmt.Sprintf("%s:user:%s", config.Account, userID)
	return c.RotateAPIKey(roleID)
}

// RotateHostAPIKey constructs a role ID from a given host ID then replaces the
// API key of the role with a new random secret.
//
// The authenticated user must have update privilege on the role.
func (c *Client) RotateHostAPIKey(hostID string) ([]byte, error) {
	config := c.GetConfig()
	roleID := fmt.Sprintf("%s:host:%s", config.Account, hostID)

	return c.RotateAPIKey(roleID)
}

// RotateAPIKeyReader replaces the API key of a role on the server with a new
// random secret and returns it as a data stream.
//
// The authenticated user must have update privilege on the role.
func (c *Client) RotateAPIKeyReader(roleID string) (io.ReadCloser, error) {
	resp, err := c.rotateAPIKey(roleID)
	if err != nil {
		return nil, err
	}

	return response.SecretDataResponse(resp)
}

func (c *Client) rotateAPIKey(roleID string) (*http.Response, error) {
	req, err := c.RotateAPIKeyRequest(roleID)
	if err != nil {
		return nil, err
	}

	return c.SubmitRequest(req)
}
