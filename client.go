package conjurapi

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	Account      string
	APIKey       string
	ApplianceUrl string
	Username     string
}

type Client struct {
	config     Config
	AuthToken  string
	httpClient *http.Client
}

func NewClient(c Config) *Client {
	return &Client{
		config:     c,
		httpClient: &http.Client{},
	}
}

func (c *Client) getAuthToken() (string, error) {
	authUrl := fmt.Sprintf("%s/authn/%s/%s/authenticate", c.config.ApplianceUrl, c.config.Account, url.QueryEscape(c.config.Username))
	resp, err := c.httpClient.Post(
		authUrl,
		"text/plain",
		strings.NewReader(c.config.APIKey),
	)
	if err != nil {
		return "", err
	}

	switch resp.StatusCode {
	case 200:
		defer resp.Body.Close()

		var token []byte
		token, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return base64.StdEncoding.EncodeToString(token), err
	default:
		return "", fmt.Errorf("%v: %s\n", authUrl, resp.Status)
	}
}

func (c *Client) generateVariableUrl(varId string) string {
	escapedVarId := url.QueryEscape(varId)
	return fmt.Sprintf("%s/secrets/%s/variable/%s", c.config.ApplianceUrl, c.config.Account, escapedVarId)
}

func (c *Client) createAuthRequest(req *http.Request) (error) {
	token, err := c.getAuthToken()
	if err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Token token=\"%s\"", token),
	)

	return nil
}

func (c *Client) RetrieveVariable(variableIdentifier string) (string, error) {
	variableUrl := c.generateVariableUrl(variableIdentifier)
	req, err := http.NewRequest("GET", variableUrl, nil)
	if err != nil {
		return "", err
	}

	err = c.createAuthRequest(req)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	switch resp.StatusCode {
	case 404:
		return "", fmt.Errorf("%v: Variable '%s' not found\n", resp.StatusCode, variableIdentifier)
	case 403:
		return "", fmt.Errorf("%v: Invalid permissions on '%s'\n", resp.StatusCode, variableIdentifier)
	case 200:
		body, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			return "", err
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("%v: %s\n", resp.StatusCode, resp.Status)
	}
}
