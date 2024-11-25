package conjurapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// Resource contains information about the Conjur Resource
type Resource struct {
	/*
		There are two types of resources in conjur:
		Roles, which can be given given permissions on other resources and granted other roles, and
		Non-Role Resources, which cannot be given given permissions or granted roles.

		Types of Roles:
		   * Group
		   * Host
		   * Layer
		   * Policy
		   * User
		Types of Non-Role Resources:
		   * Variable
		   * Webservice
	*/

	//* Fields for all resources
	Identifier  string            `json:"identifier"`
	Id          string            `json:"id"`
	Type        string            `json:"type"`
	Owner       string            `json:"owner"`
	Policy      string            `json:"policy"`
	Annotations map[string]string `json:"annotations"`

	//* Field exlusively for roles
	Permitted *map[string][]string `json:"permitted,omitempty"`

	//* Fields that we do not put into json for Roles
	Permissions  *map[string][]string `json:"permissions,omitempty"`
	Members      *[]string            `json:"members,omitempty"`
	Memberships  *[]string            `json:"memberships,omitempty"`
	RestrictedTo *[]string            `json:"restricted_to,omitempty"`
}

// Resources contains Resource Structs
type Resources []Resource

type ResourceFilter struct {
	Kind   string
	Search string
	Limit  int
	Offset int
	Role   string
}

// CheckPermission determines whether the authenticated user has a specified privilege
// on a resource.
func (c *Client) CheckPermission(resourceID string, privilege string) (bool, error) {
	req, err := c.CheckPermissionRequest(resourceID, privilege)
	if err != nil {
		return false, err
	}

	return c.processPermissionCheck(req)
}

// CheckPermissionForRole determines whether the provided role has a specific
// privilege on a resource.
func (c *Client) CheckPermissionForRole(resourceID string, roleID string, privilege string) (bool, error) {
	req, err := c.CheckPermissionForRoleRequest(resourceID, roleID, privilege)
	if err != nil {
		return false, err
	}

	return c.processPermissionCheck(req)
}

func (c *Client) processPermissionCheck(req *http.Request) (bool, error) {
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	} else if resp.StatusCode == 404 || resp.StatusCode == 403 {
		return false, nil
	} else {
		return false, fmt.Errorf("Permission check failed with HTTP status %d", resp.StatusCode)
	}
}

// ResourceExists checks whether or not a resource exists
func (c *Client) ResourceExists(resourceID string) (bool, error) {
	req, err := c.ResourceRequest(resourceID)
	if err != nil {
		return false, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return false, err
	}

	if (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == 403 {
		return true, nil
	} else if resp.StatusCode == 404 {
		return false, nil
	} else {
		return false, fmt.Errorf("Resource exists check failed with HTTP status %d", resp.StatusCode)
	}
}

// Resource fetches a single user-visible resource by id.
func (c *Client) Resource(resourceID string) (resource map[string]interface{}, err error) {
	req, err := c.ResourceRequest(resourceID)
	if err != nil {
		return
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return
	}

	data, err := response.DataResponse(resp)
	if err != nil {
		return
	}

	resource = make(map[string]interface{})
	err = json.Unmarshal(data, &resource)
	return
}

// Resources fetches user-visible resources. The set of resources can
// be limited by the given ResourceFilter. If filter is non-nil, only
// non-zero-valued members of the filter will be applied.
func (c *Client) Resources(filter *ResourceFilter) (resources []map[string]interface{}, err error) {
	req, err := c.ResourcesRequest(filter)
	if err != nil {
		return
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return
	}

	data, err := response.DataResponse(resp)
	if err != nil {
		return
	}

	resources = make([]map[string]interface{}, 1)
	err = json.Unmarshal(data, &resources)
	return
}

func (c *Client) ResourceIDs(filter *ResourceFilter) ([]string, error) {
	resources, err := c.Resources(filter)

	if err != nil {
		return nil, err
	}

	resourceIDs := make([]string, 0)

	for _, element := range resources {
		resourceIDs = append(resourceIDs, element["id"].(string))
	}

	return resourceIDs, nil
}

// PermittedRoles lists the roles which have the named permission on a resource
func (c *Client) PermittedRoles(resourceID, privilege string) ([]string, error) {
	req, err := c.PermittedRolesRequest(resourceID, privilege)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	data, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	roles := make([]string, 0)
	err = json.Unmarshal(data, &roles)
	return roles, nil
}
