package conjurapi

import (
	"github.com/cyberark/conjur-api-go/conjurapi/response"	
)

func (c *Client) RetrieveSecret(variableId string) ([]byte, error) {
	req, err := c.router.RetrieveSecretRequest(variableId)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.SecretDataResponse(resp)
}

func (c *Client) AddSecret(variableId string, secretValue string) error {
	req, err := c.router.AddSecretRequest(variableId, secretValue)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}
