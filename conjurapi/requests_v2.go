package conjurapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const V2_API_HEADER string = "application/x.secretsmgr.v2beta+json"
const V2_API_OUTGOING_HEADER_ID string = "Accept"
const V2_API_INCOMING_HEADER_ID string = "Content-Type"

// Owner defines the JSON data structure used with the Conjur API v2
type Owner struct {
	Kind string `json:"kind,omitempty"`
	Id   string `json:"id,omitempty"`
}

// Branch defines the JSON data structure used with the Conjur API v2
type Branch struct {
	Name             string            `json:"name"`
	Owner            *Owner            `json:"owner,omitempty"`
	Branch           string            `json:"branch"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors"`
	RestrictedTo     []string          `json:"restricted_to,omitempty"`
}

type AuthnDescriptorData struct {
	Claims map[string]string `json:"claims,omitempty"`
}

type AuthnDescriptor struct {
	Type      string               `json:"type"`
	ServiceID string               `json:"service_id,omitempty"`
	Data      *AuthnDescriptorData `json:"data,omitempty"`
}

type Workload struct {
	Name             string            `json:"name"`
	Branch           string            `json:"branch"`
	Type             string            `json:"type,omitempty"`
	Owner            *Owner            `json:"owner,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors"`
	RestrictedTo     []string          `json:"restricted_to,omitempty"`
}

func (c *ClientV2) CreateAuthenticatorRequest(authenticator *AuthenticatorBase) (*http.Request, error) {
	body, err := json.Marshal(authenticator)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator request: %w", err)
	}

	request, err := http.NewRequest(
		http.MethodPost,
		c.authenticatorsURL("", ""),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

func (c *ClientV2) GetAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

func (c *ClientV2) UpdateAuthenticatorRequest(authenticatorType string, serviceID string, enabled bool) (*http.Request, error) {
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator update request: %w", err)
	}

	request, err := http.NewRequest(
		http.MethodPatch,
		c.authenticatorsURL(authenticatorType, serviceID),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)
	request.Header.Add("Content-Type", "application/json")
	return request, nil
}

func (c *ClientV2) DeleteAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodDelete,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

func (c *ClientV2) ListAuthenticatorsRequest() (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL("", ""),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

func (c *ClientV2) authenticatorsURL(authenticatorType string, serviceID string) string {
	// If running against Conjur Cloud, the account is not used in the URL.
	account := c.config.Account
	if isConjurCloudURL(c.config.ApplianceURL) {
		account = ""
	}

	// TODO: validate GCP does not use service IDs and if it should be accessible via this API
	if authenticatorType == "gcp" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType).String()
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType, serviceID).String()
	}

	// For the default authenticators service endpoint
	return makeRouterURL(c.config.ApplianceURL, "authenticators", account).String()
}

// CreateBranchRequest requires branch data structure
func (c *ClientV2) CreateBranchRequest(account string, branch Branch) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if branch.Branch == "" {
		errors = append(errors, "Must specify an Branch.Branch")
	}
	if branch.Name == "" {
		errors = append(errors, "Must specify an Branch.Name")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	branchJson, err := json.Marshal(branch)

	url := fmt.Sprintf("branches/%s", account)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodPost,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

// ReadBranchRequest requires branch data structure
func (c *ClientV2) ReadBranchRequest(account string, identifier string) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if identifier == "" {
		errors = append(errors, "Must specify an identifier")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	url := fmt.Sprintf("branches/%s/%s", account, identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

// ReadBranchesRequest requires branch data structure
func (c *ClientV2) ReadBranchesWithOffsetAndLimitRequest(account string, offset uint, limit uint) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}

	if limit == 0 {
		limit = c.default_max_entries_read_limit
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	url := fmt.Sprintf("branches/%s", account)

	branchURL := ""
	if offset == 0 && limit == 0 {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).String()
	} else if limit > 0 && offset == 0 {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("limit=%d", limit).String()
	} else if offset > 0 && limit == 0 {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("offset=%d", offset).String()
	} else {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("offset=%d&limit=%d", offset, limit).String()
	}

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

// ReadBranch
func (c *ClientV2) ReadBranchesWithOffsetRequest(account string, offset uint) (*http.Request, error) {
	return c.ReadBranchesWithOffsetAndLimitRequest(account, offset, 0)
}

// ReadBranch
func (c *ClientV2) ReadBranchesRequest(account string) (*http.Request, error) {
	return c.ReadBranchesWithOffsetAndLimitRequest(account, 0, 0)
}

// UpdateBranchRequest
func (c *ClientV2) UpdateBranchRequest(account string, branch Branch) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if branch.Branch == "" {
		errors = append(errors, "Must specify an Branch.Branch")
	}
	if branch.Name == "" {
		errors = append(errors, "Must specify an Branch.Name")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	branchJson, err := json.Marshal(branch)

	url := fmt.Sprintf("branches/%s/%s", account, branch.Branch)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodPatch,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

// DeleteBranchRequest
func (c *ClientV2) DeleteBranchRequest(account string, identifier string) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if identifier == "" {
		errors = append(errors, "Must specify an Identifier")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	url := fmt.Sprintf("branches/%s/%s", account, identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodDelete,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)

	return request, nil
}

func (c *ClientV2) CreateWorkloadRequest(account string, workload Workload) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if workload.Name == "" {
		errors = append(errors, "Must specify a Workload Name")
	}
	if workload.Branch == "" {
		errors = append(errors, "Must specify a Branch")
	}
	if len(workload.AuthnDescriptors) == 0 {
		errors = append(errors, "Must specify at least one authenticator in authn_descriptors")
	} else {
		for i, d := range workload.AuthnDescriptors {
			if d.Type == "" {
				errors = append(errors, fmt.Sprintf("authn_descriptors[%d] missing type", i))
			}
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}
	// Default type
	if workload.Type == "" {
		workload.Type = "other"
	}

	payload, err := json.Marshal(workload)
	if err != nil {
		return nil, err
	}

	urlPath := fmt.Sprintf("workloads/%s", account)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)
	return req, nil
}

func (c *ClientV2) DeleteWorkloadRequest(account string, workloadID string) (*http.Request, error) {
	errors := []string{}

	if account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if workloadID == "" {
		errors = append(errors, "Must specify a Workload ID")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	urlPath := fmt.Sprintf("workloads/%s/%s", account, workloadID)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(V2_API_OUTGOING_HEADER_ID, V2_API_HEADER)
	return req, nil
}
