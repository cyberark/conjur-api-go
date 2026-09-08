package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

type GroupMember struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func (c *ClientV2) AddGroupMember(groupID string, member GroupMember) (*GroupMember, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group Membership API", MinVersion)
	}

	req, err := c.AddGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[GroupMember](c, req)
}

func (c *ClientV2) RemoveGroupMember(groupID string, member GroupMember) ([]byte, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group Membership API", MinVersion)
	}

	req, err := c.RemoveGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	return submitAndReadData(c, req)
}

func (c *ClientV2) AddGroupMemberRequest(groupID string, member GroupMember) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}

	err := member.Validate()
	if err != nil {
		return nil, err
	}

	membershipURL, err := c.addGroupMembershipURL(groupID)
	if err != nil {
		return nil, err
	}

	req, err := newV2JSONRequest(http.MethodPost, membershipURL, member, v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("Failed to create add group member request: %w", err)
	}

	return req, nil
}

func (c *ClientV2) RemoveGroupMemberRequest(groupID string, member GroupMember) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}
	err := member.Validate()
	if err != nil {
		return nil, err
	}

	membershipURL, err := c.removeGroupMembershipURL(groupID, member)
	if err != nil {
		return nil, err
	}

	req, err := newV2Request(http.MethodDelete, membershipURL, v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("Failed to create remove group member request: %v", err)
	}

	return req, nil
}

func (member GroupMember) Validate() error {
	var errs []error
	if member.ID == "" || member.Kind == "" {
		errs = append(errs, fmt.Errorf("Must specify a Member"))
	}

	switch member.Kind {
	case "user", "host", "group":
	default:
		errs = append(errs, fmt.Errorf("Invalid member kind: %v", member.Kind))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *ClientV2) addGroupMembershipURL(groupID string) (string, error) {
	escapedGroup, err := escapeGroupIdentifier("Group ID", groupID)
	if err != nil {
		return "", err
	}
	return c.groupPathURL(escapedGroup, "members"), nil
}

func (c *ClientV2) removeGroupMembershipURL(groupID string, member GroupMember) (string, error) {
	// The group id and member id both map to *glob path parameters, so their
	// own slashes are meaningful path separators and must be preserved — but any
	// other URL-significant characters (spaces, '@', '#', '?', …) must be
	// escaped, and empty/"."/".." segments rejected, or the URL is malformed or
	// vulnerable to path traversal. escapeGroupIdentifier handles both.
	escapedGroup, err := escapeGroupIdentifier("Group ID", groupID)
	if err != nil {
		return "", err
	}
	escapedMember, err := escapeGroupIdentifier("Member ID", member.ID)
	if err != nil {
		return "", err
	}
	return c.groupPathURL(escapedGroup, "members", url.PathEscape(member.Kind), escapedMember), nil
}
