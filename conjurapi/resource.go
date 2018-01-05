package conjurapi

import (
	"fmt"
)

func (c *Client) CheckPermission(resourceId, privilege string) (bool, error) {
	req, err := c.router.CheckPermissionRequest(resourceId, privilege)
	if err != nil {
		return false, err
	}

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
