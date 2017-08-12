package conjurapi

import (
	"fmt"
	"net/url"
	"strings"
	"io/ioutil"
	"net/http"
	"encoding/base64"
	"time"
)

func (c *client) authUrl() (string) {
	return fmt.Sprintf("%s/authn/%s/%s/authenticate", c.config.ApplianceURL, c.config.Account, url.QueryEscape(c.config.Username))
}

func (c *client) getAuthToken() (string, error) {
	switch {
	case len(c.config.AuthnTokenFile) > 0:
		return waitForTextFile(c.config.AuthnTokenFile, time.After(time.Second * 10))
	case len(c.config.Username) > 0 && len(c.config.APIKey) > 0:
		return c.getAuthTokenByLogin()
	default:
		return "", fmt.Errorf("Missing at least 1 means of authentication.")
	}
}

func (c *client) getAuthTokenByLogin() (string, error) {
	resp, err := c.httpclient.Post(
		c.authUrl(),
		"text/plain",
		strings.NewReader(c.config.APIKey),
	)
	if err != nil {
		return "", err
	}

	switch resp.StatusCode {
	case 200:
		defer resp.Body.Close()

		var tokenPayload []byte
		tokenPayload, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return string(tokenPayload), err
	default:
		return "", fmt.Errorf("%v: %s\n", resp.StatusCode, resp.Status)
	}
}


func (c *client) createAuthRequest(req *http.Request) (error) {
	token, err := c.getAuthToken()
	if err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Token token=\"%s\"",  base64.StdEncoding.EncodeToString([]byte(token))),
	)

	return nil
}
