package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	req, err := c.CreateBranchRequest(branch)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[Branch](c, req)
}

func (c *ClientV2) ReadBranch(identifier string) (*Branch, error) {
	req, err := c.ReadBranchRequest(identifier)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[Branch](c, req)
}

func (c *ClientV2) ReadBranches(filter *BranchFilter) (BranchesResponse, error) {
	req, err := c.ReadBranchesRequest(filter)
	if err != nil {
		return BranchesResponse{}, err
	}

	branchResp, err := submitAndUnmarshal[BranchesResponse](c, req)
	if err != nil {
		return BranchesResponse{}, err
	}
	return *branchResp, nil
}

func (c *ClientV2) UpdateBranch(branch Branch) ([]byte, error) {
	req, err := c.UpdateBranchRequest(branch.Name, branch.Owner, branch.Annotations)
	if err != nil {
		return nil, err
	}

	return submitAndReadData(c, req)
}

func (c *ClientV2) DeleteBranch(identifier string) ([]byte, error) {
	req, err := c.DeleteBranchRequest(identifier)
	if err != nil {
		return nil, err
	}

	return submitAndReadData(c, req)
}

func (c *ClientV2) CreateBranchRequest(branch Branch) (*http.Request, error) {
	err := branch.Validate()
	if err != nil {
		return nil, err
	}

	return newV2JSONRequest(http.MethodPost, c.branchesURL(), branch, v2APIHeaderBeta)
}

func (c *ClientV2) ReadBranchRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	return newV2Request(http.MethodGet, c.branchURL(identifier), v2APIHeaderBeta)
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

	return newV2Request(http.MethodGet, requestURL, v2APIHeaderBeta)
}

func (c *ClientV2) UpdateBranchRequest(branchName string, owner *Owner, annotations map[string]string) (*http.Request, error) {
	payload := struct {
		Owner       *Owner            `json:"owner,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Owner:       owner,
		Annotations: annotations,
	}

	return newV2JSONRequest(http.MethodPatch, c.branchURL(branchName), payload, v2APIHeaderBeta)
}

func (c *ClientV2) DeleteBranchRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	return newV2Request(http.MethodDelete, c.branchURL(identifier), v2APIHeaderBeta)
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
	if c.config.IsSaaS() {
		account = ""
	}
	if identifier == "" {
		return makeRouterURL(c.config.ApplianceURL, "branches", account).String()
	}
	return makeRouterURL(c.config.ApplianceURL, "branches", account, identifier).String()
}

func (c *ClientV2) branchesURL() string {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "branches", account).String()
}
