package conjurapi

import (
	"fmt"
	"io/ioutil"
	"encoding/base64"
	"net/http"
	"io"
)

func (c *Client) loadPolicy(policyIdentifier string, policy io.Reader) (string, error) {
	policyUrl := fmt.Sprintf("%s/policies/%s/policy/%s}", c.config.ApplianceUrl, c.config.Account, policyIdentifier)
	req, err := http.NewRequest(
		"PUT",
		policyUrl,
		policy,
	)
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
	case 201:
		defer resp.Body.Close()

		var token []byte
		token, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return base64.StdEncoding.EncodeToString(token), err
	default:
		return "", fmt.Errorf("%v: %s\n", resp.StatusCode, resp.Status)
	}
}
