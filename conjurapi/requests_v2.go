package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const v2APIHeader string = "application/x.secretsmgr.v2beta+json"
const v2APIOutgoingHeaderID string = "Accept"
const v2APIIncomingHeaderID string = "Content-Type"

// Owner defines the JSON data structure used with the Conjur API v2
type Owner struct {
	Kind string `json:"kind,omitempty"`
	Id   string `json:"id,omitempty"`
}

// Branch defines the JSON data structure used with the Conjur API v2
type Branch struct {
	Name        string            `json:"name"`
	Owner       *Owner            `json:"owner,omitempty"`
	Branch      string            `json:"branch"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type BranchesResponse struct {
	Branches []Branch `json:"branches,omitempty"`
	Count    int      `json:"count"`
}

type BranchFilter struct {
	Limit  int
	Offset int
}

func (b Branch) Validate() error {
	var errs []error
	if b.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required Branch attribute Branch"))
	}
	if b.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required Branch attribute Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
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

func (w Workload) Validate() error {
	var errs []error
	if w.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Branch"))
	}
	if w.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
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
	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

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

func (c *ClientV2) CreateBranchRequest(branch Branch) (*http.Request, error) {
	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}
	err := branch.Validate()
	if err != nil {
		return nil, err
	}

	branchJson, err := json.Marshal(branch)

	path := fmt.Sprintf("branches/%s", c.config.Account)

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodPost,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) ReadBranchRequest(identifier string) (*http.Request, error) {
	errors := []string{}

	if c.config.Account == "" {
		errors = append(errors, "Must specify an Account")
	}
	if identifier == "" {
		errors = append(errors, "Must specify an identifier")
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}

	url := fmt.Sprintf("branches/%s/%s", c.config.Account, identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) ReadBranchesRequest(filter *BranchFilter) (*http.Request, error) {
	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}

	url := fmt.Sprintf("branches/%s", c.config.Account)

	branchURL := ""
	if filter == nil {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).String()
	} else if filter.Limit > 0 && filter.Offset <= 0 {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("limit=%d", filter.Limit).String()
	} else if filter.Offset > 0 && filter.Limit <= 0 {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("offset=%d", filter.Offset).String()
	} else {
		branchURL = makeRouterURL(c.config.ApplianceURL, url).withFormattedQuery("offset=%d&limit=%d", filter.Offset, filter.Limit).String()
	}

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) UpdateBranchRequest(branch Branch) (*http.Request, error) {
	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}
	err := branch.Validate()
	if err != nil {
		return nil, err
	}

	branchJson, err := json.Marshal(branch)

	url := fmt.Sprintf("branches/%s/%s", c.config.Account, branch.Branch)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodPatch,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) DeleteBranchRequest(identifier string) (*http.Request, error) {
	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	url := fmt.Sprintf("branches/%s/%s", c.config.Account, identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodDelete,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) CreateWorkloadRequest(workload Workload) (*http.Request, error) {
	errors := []string{}

	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}
	err := workload.Validate()
	if err != nil {
		return nil, err
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

	urlPath := fmt.Sprintf("workloads/%s", c.config.Account)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
	return req, nil
}

func (c *ClientV2) DeleteWorkloadRequest(workloadID string) (*http.Request, error) {
	if c.config.Account == "" {
		return nil, fmt.Errorf("Must specify an Account")
	}
	if workloadID == "" {
		return nil, fmt.Errorf("Must specify a Workload ID")
	}

	urlPath := fmt.Sprintf("workloads/%s/%s", c.config.Account, workloadID)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
	return req, nil
}
