package conjurapi

import (
	"io"

	"github.com/cyberark/conjur-api-go/conjurapi/response"	
)

func (c *Client) LoadPolicy(policyId string, policy io.Reader) (map[string]interface{}, error) {
	req, err := c.router.LoadPolicyRequest(policyId, policy)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := make(map[string]interface{})
	return obj, response.JSONResponse(resp, &obj)
}
