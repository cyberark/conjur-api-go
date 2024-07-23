package conjurapi

import (
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// EnableAuthenticator enables or disables an authenticator instance
//
// The authenticated user must be admin
func (c *Client) EnableAuthenticator(authenticatorType string, serviceID string, enabled bool) error {
	req, err := c.EnableAuthenticatorRequest(authenticatorType, serviceID, enabled)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	err = response.EmptyResponse(resp)
	if err != nil {
		return err
	}

	return nil
}
