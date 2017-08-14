package conjurapi

import (
	"fmt"
	"net/url"
	"strings"
	"io/ioutil"
	"net/http"
	"time"
	"encoding/json"
)

func (c *client) authenticateUrl() (string) {
	return fmt.Sprintf("%s/authn/%s/%s/authenticate", c.config.ApplianceURL, c.config.Account, url.QueryEscape(c.config.Username))
}

func (c *client) getAuthToken() ([]byte, error) {
	var (
		tokenBytes []byte
		err error
	)

	switch {
	case len(c.config.AuthnTokenFile) > 0:
		tokenBytes, err = waitForTextFile(c.config.AuthnTokenFile, time.After(time.Second*10))
	case len(c.config.Username) > 0 && len(c.config.APIKey) > 0:
		tokenBytes, err = c.getAuthTokenByLogin()
	default:
		err = fmt.Errorf("Missing at least 1 means of authentication.")
	}

	return tokenBytes, err
}

func (c *client) authenticate() (error) {
	if c.authToken.ValidAtTime(time.Now()) {
		return nil
	}
	var token AuthnToken

	tokenBytes, err := c.getAuthToken()
	if err == nil {
		if err = json.Unmarshal(tokenBytes, &token); err == nil && token.Key != "" {
			c.authToken = token
		}
	}

	return err
}

func (c *client) getAuthTokenByLogin() ([]byte, error) {
	resp, err := c.httpclient.Post(
		c.authenticateUrl(),
		"text/plain",
		strings.NewReader(c.config.APIKey),
	)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case 200:
		defer resp.Body.Close()

		var tokenPayload []byte
		tokenPayload, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return tokenPayload, err
	default:
		return nil, fmt.Errorf("%v: %s\n", resp.StatusCode, resp.Status)
	}
}

func (c *client) createAuthRequest(req *http.Request) (error) {
	if err := c.authenticate(); err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Token token=\"%s\"", c.authToken.Base64encoded),
	)

	return nil
}
