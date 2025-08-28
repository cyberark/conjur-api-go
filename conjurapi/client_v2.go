package conjurapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

const MinVersion = "1.23.0"

// The V2Client struct is a sub-client for interacting with the v2 APIs in Conjur, which
// are not supported in all versions.
type ClientV2 struct {
	*Client
	default_max_entries_read_limit uint
}

func (c *ClientV2) CreateBranch(branch Branch) ([]byte, error) {
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than %s", MinVersion)
	}

	req, err := c.CreateBranchRequest(branch)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) ReadBranch(identifier string) ([]byte, error) {
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than %s", MinVersion)
	}

	req, err := c.ReadBranchRequest(identifier)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) ReadBranches(filter *BranchFilter) (BranchesResponse, error) {
	branchResp := BranchesResponse{}
	if isConjurCloudURL(c.config.ApplianceURL) {
		return branchResp, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return branchResp, fmt.Errorf("Create Branch is not supported in Conjur versions older than %s", MinVersion)
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
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than %s", MinVersion)
	}
	req, err := c.UpdateBranchRequest(branch)
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
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than %s", MinVersion)
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

func (c *ClientV2) CreateWorkload(workload Workload) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Create Workload is not supported in Conjur Enterprise/OSS")
	}

	req, err := c.CreateWorkloadRequest(workload)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) DeleteWorkload(workloadId string) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Delete Workload is not supported in Conjur Enterprise/OSS")
	}

	req, err := c.DeleteWorkloadRequest(workloadId)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}
