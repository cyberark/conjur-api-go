package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Branch API %s", NotSupportedInConjurCloud)
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
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
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Branch API %s", NotSupportedInConjurCloud)
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
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
	if isConjurCloudURL(c.config.ApplianceURL) {
		return branchResp, fmt.Errorf(NotSupportedInConjurCloud, "Branch API")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
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
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf(NotSupportedInConjurCloud, "Branch API")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
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
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf(NotSupportedInConjurCloud, "Branch API")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) ReadBranchRequest(identifier string) (*http.Request, error) {
	errors := []string{}

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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) ReadBranchesRequest(filter *BranchFilter) (*http.Request, error) {
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

	url := fmt.Sprintf("branches/%s/%s", c.config.Account, branchName)
	branchURL := makeRouterURL(c.config.ApplianceURL, url).String()

	request, err := http.NewRequest(
		http.MethodPatch,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) DeleteBranchRequest(identifier string) (*http.Request, error) {
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
