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
	APIKey string `json:"api_key,omitempty"`
}

// PolicyResponse contains information about the policy update.
type PolicyResponse struct {
	// Newly created roles.
	CreatedRoles map[string]CreatedRole `json:"created_roles"`
	// The version number of the policy.
	Version uint32 `json:"version"`
}

// DryRunPolicyResponseItems contains Conjur Resources.
type DryRunPolicyResponseItems struct {
	Items []Resource `json:"items"`

// DryRunErrors contains information about any errors that occurred during
// policy validation.
type DryRunErrors struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// DryRunPolicyResponse contains information about the policy validation and
// whether it was successful.
type DryRunPolicyResponse struct {
	// Status of the policy validation.
	Status  string                   `json:"status"`
	Created DryRunPolicyResonseItems `json:"created"`
	Errors  []DryRunErrors           `json:"errors"`
}

// LoadPolicy submits new policy data or policy changes to the server.
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

func (c *Client) DryRunPolicy(mode PolicyMode, policyID string, policy io.Reader) (*DryRunPolicyResponse, error) {
	req, err := c.LoadPolicyRequest(mode, policyID, policy, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	policyResponse := DryRunPolicyResponse{}
	return &policyResponse, response.DryRunPolicyJSONResponse(resp, &policyResponse)
}

// FetchPolicy creates a request to fetch policy from the system
func (c *Client) FetchPolicy(policyID string, returnJSON bool, policyTreeDepth uint, sizeLimit uint) ([]byte, error) {
	req, err := c.fetchPolicyRequest(policyID, returnJSON, policyTreeDepth, sizeLimit)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}
