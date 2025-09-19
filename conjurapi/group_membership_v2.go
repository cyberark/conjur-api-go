package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type GroupMember struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func (c *ClientV2) AddGroupMember(groupID string, member GroupMember) (*GroupMember, error) {
	memberResp := GroupMember{}

	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Add Group Member is not supported in Conjur Enterprise/OSS")
	}

	req, err := c.AddGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return &memberResp, response.JSONResponse(resp, &memberResp)
}

func (c *ClientV2) RemoveGroupMember(groupID string, member GroupMember) ([]byte, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("Remove Group Member is not supported in Conjur Enterprise/OSS")
	}
	req, err := c.RemoveGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) AddGroupMemberRequest(groupID string, member GroupMember) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}

	err := member.Validate()
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(member)
	if err != nil {
		return nil, err
	}

	urlPath := fmt.Sprintf("groups/%s/members", groupID)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("Failed to create add group member request: %w", err)
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
	req.Header.Add(v2APIIncomingHeaderID, "application/json")
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

	urlPath := fmt.Sprintf("groups/%s/members/%s/%s", groupID, member.Kind, member.ID)
	fullURL := makeRouterURL(c.config.ApplianceURL, urlPath).String()

	req, err := http.NewRequest(http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create remove group member request: %v", err)
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)
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
