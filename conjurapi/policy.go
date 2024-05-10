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

// CreatedRole contains the full role ID and API key of a role which was created
// by the server when loading a policy.
type CreatedRole struct {
	ID     string `json:"id"`
	APIKey string `json:"api_key"`
}

// PolicyResponse contains information about the policy update.
type PolicyResponse struct {
	// Newly created roles.
	CreatedRoles map[string]CreatedRole `json:"created_roles"`
	// The version number of the policy.
	Version uint32 `json:"version"`
}

// ValidationErrors contains information about any errors that occurred during
// policy validation.
type ValidationErrors struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// ValidatePolicyResponse contains information about the policy validation and
// whether it was successful.
type ValidatePolicyResponse struct {
	// Status of the policy validation.
	Status string             `json:"status"`
	Errors []ValidationErrors `json:"errors"`
}

// LoadPolicy submits new policy data or polciy changes to the server.
//
// The required permission depends on the mode.
func (c *Client) LoadPolicy(mode PolicyMode, policyID string, policy io.Reader) (*PolicyResponse, error) {
	req, err := c.LoadPolicyRequest(mode, policyID, policy, false)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	policyResponse := PolicyResponse{}
	return &policyResponse, response.JSONResponse(resp, &policyResponse)
}

func (c *Client) ValidatePolicy(mode PolicyMode, policyID string, policy io.Reader) (*ValidatePolicyResponse, error) {
	req, err := c.LoadPolicyRequest(mode, policyID, policy, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	policyResponse := ValidatePolicyResponse{}
	return &policyResponse, response.PolicyValidationResponse(resp, &policyResponse)
}
