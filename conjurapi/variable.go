package conjurapi

import (
	"io"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// RetrieveSecret fetches a secret from a variable.
//
// The authenticated user must have execute privilege on the variable.
func (c *Client) RetrieveSecret(variableID string) ([]byte, error) {
	resp, err := c.retrieveSecret(variableID)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// RetrieveSecretReader fetches a secret from a variable and returns it as a
// data stream.
//
// The authenticated user must have execute privilege on the variable.
func (c *Client) RetrieveSecretReader(variableID string) (io.ReadCloser, error) {
	resp, err := c.retrieveSecret(variableID)
	if err != nil {
		return nil, err
	}

	return response.SecretDataResponse(resp)
}
func (c *Client) retrieveSecret(variableID string) (*http.Response, error) {
	req, err := c.router.RetrieveSecretRequest(variableID)
	if err != nil {
		return nil, err
	}

	return c.SubmitRequest(req)
}

// AddSecret adds a secret value to a variable.
//
// The authenticated user must have update privilege on the variable.
func (c *Client) AddSecret(variableID string, secretValue string) error {
	req, err := c.router.AddSecretRequest(variableID, secretValue)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}
