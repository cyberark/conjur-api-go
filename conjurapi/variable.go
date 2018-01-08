package conjurapi

import (
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/wrapper"
	"github.com/cyberark/conjur-api-go/conjurapi/wrapper_v4"
)

func (c *Client) RetrieveSecret(variableId string) ([]byte, error) {
	var (
		req *http.Request
		err error
	)

	if c.config.V4 {
		req, err = wrapper_v4.RetrieveSecretRequest(c.config.ApplianceURL, variableId)
	} else {
		req, err = wrapper.RetrieveSecretRequest(c.config.ApplianceURL, makeFullId(c.config.Account, "variable", variableId))
	}

	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	if c.config.V4 {
		return wrapper_v4.RetrieveSecretResponse(resp)
	} else {
		return wrapper.RetrieveSecretResponse(resp)
	}
}

func (c *Client) AddSecret(variableId string, secretValue string) error {
	var (
		req *http.Request
		err error
	)

	if c.config.V4 {
		err = fmt.Errorf("AddSecret is not supported for Conjur V4")
	} else {
		req, err = wrapper.AddSecretRequest(c.config.ApplianceURL, makeFullId(c.config.Account, "variable", variableId), secretValue)
	}

	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return wrapper.AddSecretResponse(resp)
}
