package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Owner struct {
	Kind string `json:"kind,omitempty"`
	Id   string `json:"id,omitempty"`
}

type Branch struct {
	Name string `json:"name"`
	// Owner is sent on create. Only Self-Hosted returns it and lets
	// UpdateBranch change it; SaaS answers an owner in an update with a 422.
	Owner       *Owner            `json:"owner,omitempty"`
	Branch      string            `json:"branch"`
	Annotations map[string]string `json:"annotations,omitempty"`
	// CreatedAt is set by the server. Only SaaS sends it.
	CreatedAt string `json:"created_at,omitempty"`
}

type BranchesResponse struct {
	Branches []Branch `json:"branches,omitempty"`
	Count    int      `json:"count"` // grand total, not the page size
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

// ReadBranches gets a page of branches; filter may be nil. To read them all,
// advance filter.Offset by the length of each page until it reaches Count.
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

// UpdateBranch adds or replaces branch.Annotations on the branch, without
// removing the others, sets branch.Owner if given, and returns the branch.
func (c *ClientV2) UpdateBranch(branch Branch) (*Branch, error) {
	req, err := c.UpdateBranchRequest(branch.identifier(), branch.Owner, branch.Annotations)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[Branch](c, req)
}

// DeleteBranch deletes a branch and everything under it, secrets included. The
// server doesn't refuse a branch that still holds resources.
func (c *ClientV2) DeleteBranch(identifier string) error {
	req, err := c.DeleteBranchRequest(identifier)
	if err != nil {
		return err
	}

	return submitAndEmpty(c, req)
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

	branchURL, err := c.branchURL(identifier)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodGet, branchURL, v2APIHeaderBeta)
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

// UpdateBranchRequest builds the branch PATCH request. A nil owner is not sent.
func (c *ClientV2) UpdateBranchRequest(branchName string, owner *Owner, annotations map[string]string) (*http.Request, error) {
	if branchName == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	payload := struct {
		Owner       *Owner            `json:"owner,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Owner:       owner,
		Annotations: annotations,
	}

	branchURL, err := c.branchURL(branchName)
	if err != nil {
		return nil, err
	}
	return newV2JSONRequest(http.MethodPatch, branchURL, payload, v2APIHeaderBeta)
}

func (c *ClientV2) DeleteBranchRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	branchURL, err := c.branchURL(identifier)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodDelete, branchURL, v2APIHeaderBeta)
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

// identifier joins Branch and Name; with no Branch, Name is the full identifier.
func (b Branch) identifier() string {
	if b.Branch == "" {
		return b.Name
	}
	return b.Branch + "/" + b.Name
}

// branchURL escapes each identifier segment, rejecting empty, "." and ".." ones.
func (c *ClientV2) branchURL(identifier string) (string, error) {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	if identifier == "" {
		return makeRouterURL(c.config.ApplianceURL, "branches", account).String(), nil
	}
	escaped, err := escapePathSegments("Branch identifier", strings.Split(identifier, "/"))
	if err != nil {
		return "", err
	}
	components := []string{"branches"}
	if account != "" {
		components = append(components, account)
	}
	components = append(components, escaped...)
	return makeRouterURL(c.config.ApplianceURL, components...).String(), nil
}

func (c *ClientV2) branchesURL() string {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "branches", account).String()
}
