package conjurapi

import (
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func (c *Client) Login(username string, password string) (apiKey []byte, err error) {
	req, err := c.router.LoginRequest(username, password)
	if err != nil {
		return
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}

	return response.DataResponse(resp)
}
