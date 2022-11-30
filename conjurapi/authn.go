package conjurapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// OidcProviderResponse contains information about an OIDC provider.
type OidcProviderResponse struct {
	ServiceID    string `json:"service_id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

func (c *Client) RefreshToken() (err error) {
	var token *authn.AuthnToken

	// Fetch cached conjur access token if using OIDC
	if c.GetConfig().AuthnType == "oidc" {
		token := c.readCachedAccessToken()
		if token != nil {
			c.authToken = token
		}
	}

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
func (c *Client) Login(login string, password string) ([]byte, error) {
	req, err := c.LoginRequest(login, password)
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

func (c *Client) OidcAuthenticate(code, nonce, code_verifier string) ([]byte, error) {
	req, err := c.OidcAuthenticateRequest(code, nonce, code_verifier)
	if err != nil {
		return nil, err
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	resp, err := response.DataResponse(res)

	if err == nil {
		c.cacheAccessToken(resp)
	}

	return resp, err
}

func (c *Client) ListOidcProviders() ([]OidcProviderResponse, error) {
	req, err := c.ListOidcProvidersRequest()
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	providers := []OidcProviderResponse{}
	err = response.JSONResponse(resp, &providers)

	return providers, err
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

func (c *Client) oidcTokenPath() string {
	oidcTokenPath := c.GetConfig().OidcTokenPath
	if oidcTokenPath == "" {
		oidcTokenPath = defaultOidcTokenPath
	}
	return oidcTokenPath
}

// Caches the conjur access token. We only cache this for OIDC since we don't have access
// to the Conjur API key and this is the only credential we can save.
// TODO: Perhaps .netrc storage should be moved to the conjur-api-go repository. At that point we could store
// the access token there as we do with the API key.
func (c *Client) cacheAccessToken(token []byte) error {
	if token == nil {
		return nil
	}

	oidcTokenPath := c.oidcTokenPath()

	// Ensure the directory exists
	_, err := os.Stat(oidcTokenPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		dir := filepath.Dir(oidcTokenPath)
		os.MkdirAll(dir, os.ModePerm)
	}
	err = os.WriteFile(oidcTokenPath, token, 0600)
	if err != nil {
		logging.ApiLog.Debugf("Failed to write access token to %s: %s", oidcTokenPath, err)
	}
	return nil
}

// Fetches the cached conjur access token. We only do this for OIDC since we don't have access
// to the Conjur API key and this is the only credential we can save.
func (c *Client) readCachedAccessToken() *authn.AuthnToken {
	if contents, err := os.ReadFile(c.oidcTokenPath()); err == nil {
		token, err := authn.NewToken(contents)
		if err == nil {
			token.FromJSON(contents)
			return token
		}
	}
	return nil
}
