package conjurapi

import (
	"fmt"
	"io"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/wrapper"
)

func (c *Client) LoadPolicy(policyId string, policy io.Reader) (map[string]interface{}, error) {
	var (
		req *http.Request
		err error
	)

	if c.config.V4 {
		err = fmt.Errorf("LoadPolicy is not supported for Conjur V4")
	} else {
		req, err = wrapper.LoadPolicyRequest(c.config.ApplianceURL, makeFullId(c.config.Account, "policy", policyId), policy)
	}

	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return wrapper.LoadPolicyResponse(resp)
}
