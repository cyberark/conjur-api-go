package conjurapi

import (
	"io"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// PolicyMode defines the server-sized behavior when loading a policy.
type PolicyMode uint

const (
	// PolicyModePost appends new data to the policy.
	PolicyModePost PolicyMode = 1
	// PolicyModePut completely replaces the policy, implicitly deleting data which is not present in the new policy.
	PolicyModePut PolicyMode = 2
	// PolicyModePatch adds policy data and explicitly deletes policy data.
	PolicyModePatch PolicyMode = 3
)

// LoadPolicy submits new policy data or polciy changes to the server.
//
// The required permission depends on the mode.
func (c *Client) LoadPolicy(mode PolicyMode, policyID string, policy io.Reader) (map[string]interface{}, error) {
	req, err := c.router.LoadPolicyRequest(mode, policyID, policy)
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
