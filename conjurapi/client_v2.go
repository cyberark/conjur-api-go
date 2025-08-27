package conjurapi

import (
	"errors"
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

const MinVersion = "1.23.0"

type Status int

const (
	Unset Status = iota
	True
	False
)

// The V2Client struct is a sub-client for interacting with the v2 APIs in Conjur, which
// are not supported in all versions.
type ClientV2 struct {
	*Client
	default_max_entries_read_limit uint
	isConjurCloudStatus            Status
	conjurVersion                  string
}

func (c *ClientV2) IsConjurCloud(url string) bool {
	if c.isConjurCloudStatus == Unset {
		if isConjurCloudURL(url) {
			c.isConjurCloudStatus = True
			return true
		} else {
			c.isConjurCloudStatus = False
			return false
		}
	} else if c.isConjurCloudStatus == True {
		return true
	}
	return false
}

func (c *ClientV2) VerifyMinServerVersionV2(minVersion string) error {
	serverVersion := ""
	if c.conjurVersion == "" {
		serverVersion, err := c.ServerVersion()
		if err != nil {
			return err
		}
		c.conjurVersion = serverVersion
	}

	return validateMinVersion(serverVersion, minVersion)
}

// CreateBranch
func (c *ClientV2) CreateBranch(account string, branch Branch) ([]byte, error) {
	if c.IsConjurCloud(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersionV2(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than 1.21.1")
	}

	req, err := c.CreateBranchRequest(account, branch)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// ReadBranch
func (c *ClientV2) ReadBranch(account string, identifier string) ([]byte, error) {
	if c.IsConjurCloud(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersionV2(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than 1.21.1")
	}

	req, err := c.ReadBranchRequest(account, identifier)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// ReadBranch
func (c *ClientV2) ReadBranchesWithOffsetAndLimit(account string, offset uint, limit uint) ([]byte, error) {
	if c.IsConjurCloud(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersionV2(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than 1.21.1")
	}

	req, err := c.ReadBranchesWithOffsetAndLimitRequest(account, offset, limit)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// ReadBranch
func (c *ClientV2) ReadBranchesWithOffset(account string, offset uint) ([]byte, error) {
	return c.ReadBranchesWithOffsetAndLimit(account, offset, 500)
}

// ReadBranch
func (c *ClientV2) ReadBranches(account string) ([]byte, error) {
	return c.ReadBranchesWithOffsetAndLimit(account, 0, 500)
}

// UpdateBranch
func (c *ClientV2) UpdateBranch(account string, branch Branch) ([]byte, error) {
	if c.IsConjurCloud(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersionV2(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than 1.21.1")
	}

	req, err := c.UpdateBranchRequest(account, branch)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// DeleteBranch
func (c *ClientV2) DeleteBranch(account string, identifier string) ([]byte, error) {
	if c.IsConjurCloud(c.config.ApplianceURL) {
		return nil, errors.New("Create Branch is not supported in Conjur Cloud")
	}
	err := c.VerifyMinServerVersionV2(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Branch is not supported in Conjur versions older than 1.21.1")
	}

	req, err := c.DeleteBranchRequest(account, identifier)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) CreateWorkload(account string, workload Workload) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Create Workload is not supported in Conjur Enterprise")
	}

	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Create Workload is not supported in Conjur versions older than %s", MinVersion)
	}

	req, err := c.CreateWorkloadRequest(account, workload)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) DeleteWorkload(account string, workloadId string) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Delete Workload is not supported in Conjur Enterprise")
	}

	err := c.VerifyMinServerVersion(MinVersion)
	if err != nil {
		return nil, fmt.Errorf("Delete Workload is not supported in Conjur versions older than %s", MinVersion)
	}

	req, err := c.DeleteWorkloadRequest(account, workloadId)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}
