package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"net/http"
)

type Subject struct {
	Id   string `json:"id"`
	Kind string `json:"kind"`
}

type Permission struct {
	Subject    Subject  `json:"subject,omitempty"`
	Privileges []string `json:"privileges,omitempty"`
	Href       string   `json:"href,omitempty"`
}

type PermissionResponse struct {
	Permission []Permission `json:"permissions,omitempty"`
	Count      int          `json:"count"`
}

type StaticSecret struct {
	Branch      string            `json:"branch"`
	Name        string            `json:"name"`
	MimeType    string            `json:"mime_type"`
	Owner       *Owner            `json:"owner,omitempty"`
	Value       string            `json:"value"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Permissions []Permission      `json:"permissions"`
}

type StaticSecretResponse struct {
	Branch      string            `json:"branch"`
	Name        string            `json:"name"`
	MimeType    string            `json:"mime_type"`
	Owner       *Owner            `json:"owner,omitempty"`
	Value       string            `json:"value"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Permissions Permission        `json:"permissions"`
}

func (c *ClientV2) CreateStaticSecretRequest(secret StaticSecret) (*http.Request, error) {
	err := secret.Validate()
	if err != nil {
		return nil, err
	}

	branchJson, err := json.Marshal(secret)

	path := "secrets/static"

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodPost,
		branchURL,
		bytes.NewBuffer(branchJson),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) CreateStaticSecret(secret StaticSecret) (*StaticSecretResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("StaticSecret API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.CreateStaticSecretRequest(secret)
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

	secretResp := StaticSecretResponse{}
	err = json.Unmarshal(bodyData, &secretResp)
	if err != nil {
		return nil, err
	}

	return &secretResp, nil
}

func (c *ClientV2) GetStaticSecretDetailsRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	path := fmt.Sprintf("secrets/static/%s", identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) GetStaticSecretDetails(identifier string) (*StaticSecretResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("StaticSecret API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.GetStaticSecretDetailsRequest(identifier)
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

	secretResp := StaticSecretResponse{}
	err = json.Unmarshal(bodyData, &secretResp)
	if err != nil {
		return nil, err
	}

	return &secretResp, nil
}

func (c *ClientV2) GetStaticSecretPermissionsRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	path := fmt.Sprintf("secrets/static/%s/permissions", identifier)

	branchURL := makeRouterURL(c.config.ApplianceURL, path).String()

	request, err := http.NewRequest(
		http.MethodGet,
		branchURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeader)

	return request, nil
}

func (c *ClientV2) GetStaticSecretPermissions(identifier string) (*PermissionResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf("StaticSecret API %s", NotSupportedInConjurEnterprise)
	}

	req, err := c.GetStaticSecretPermissionsRequest(identifier)
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

	permissionsResp := PermissionResponse{}
	err = json.Unmarshal(bodyData, &permissionsResp)
	if err != nil {
		return nil, err
	}

	return &permissionsResp, nil
}

func (s StaticSecret) Validate() error {
	var errs []error
	if s.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required StaticSecret attribute Branch"))
	}
	if s.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required StaticSecret attribute Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
