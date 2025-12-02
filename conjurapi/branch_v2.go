package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type Owner struct {
	Kind string `json:"kind,omitempty"`
	Id   string `json:"id,omitempty"`
}

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

func (c *ClientV2) CreateBranch(branch Branch) (*Branch, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Branch API", MinVersion)
	}

	req, err := c.CreateBranchRequest(branch)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	branchResp := Branch{}
	err = json.Unmarshal(bodyData, &branchResp)
	if err != nil {
		return nil, err
	}

	return &branchResp, nil
}

func (c *ClientV2) ReadBranch(identifier string) (*Branch, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Branch API", MinVersion)
	}

	req, err := c.ReadBranchRequest(identifier)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	branchResp := Branch{}
	err = json.Unmarshal(bodyData, &branchResp)
	if err != nil {
		return nil, err
	}

	return &branchResp, nil
}

func (c *ClientV2) ReadBranches(filter *BranchFilter) (BranchesResponse, error) {
	branchResp := BranchesResponse{}
	if !isConjurCloudURL(c.config.ApplianceURL) && c.VerifyMinServerVersion(MinVersion) != nil {
		return branchResp, fmt.Errorf(NotSupportedInOldVersions, "Branch API", MinVersion)
	}

	req, err := c.ReadBranchesRequest(filter)
	if err != nil {
		return branchResp, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return branchResp, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return branchResp, err
	}

	err = json.Unmarshal(bodyData, &branchResp)

	return branchResp, err
}

func (c *ClientV2) UpdateBranch(branch Branch) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Branch API", MinVersion)
	}
	req, err := c.UpdateBranchRequest(branch.Name, branch.Owner, branch.Annotations)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) DeleteBranch(identifier string) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Branch API", MinVersion)
	}

	req, err := c.DeleteBranchRequest(identifier)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) CreateBranchRequest(branch Branch) (*http.Request, error) {
	err := branch.Validate()
	if err != nil {
		return nil, err
	}

	branchJson, err := json.Marshal(branch)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(
		http.MethodPost,
		c.branchesURL(),
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return request, nil
}

func (c *ClientV2) ReadBranchRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	request, err := http.NewRequest(
		http.MethodGet,
		c.branchURL(identifier),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return request, nil
}

func (c *ClientV2) ReadBranchesRequest(filter *BranchFilter) (*http.Request, error) {
	baseURL := c.branchesURL()
	query := url.Values{}

	if filter != nil {
		if filter.Limit > 0 {
			query.Add("limit", fmt.Sprintf("%d", filter.Limit))
		}
		if filter.Offset > 0 {
			query.Add("offset", fmt.Sprintf("%d", filter.Offset))
		}
	}

	requestURL := baseURL
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", baseURL, encoded)
	}

	request, err := http.NewRequest(
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return request, nil
}

func (c *ClientV2) UpdateBranchRequest(branchName string, owner *Owner, annotations map[string]string) (*http.Request, error) {
	payload := struct {
		Owner       *Owner            `json:"owner,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Owner:       owner,
		Annotations: annotations,
	}

	branchJson, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(
		http.MethodPatch,
		c.branchURL(branchName),
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return request, nil
}

func (c *ClientV2) DeleteBranchRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	request, err := http.NewRequest(
		http.MethodDelete,
		c.branchURL(identifier),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return request, nil
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

func (c *ClientV2) branchURL(identifier string) string {
	account := c.config.Account
	if isConjurCloudURL(c.config.ApplianceURL) {
		account = ""
	}
	if identifier == "" {
		return makeRouterURL(c.config.ApplianceURL, "branches", account).String()
	}
	return makeRouterURL(c.config.ApplianceURL, "branches", account, identifier).String()
}

func (c *ClientV2) branchesURL() string {
	account := c.config.Account
	if isConjurCloudURL(c.config.ApplianceURL) {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "branches", account).String()
}
