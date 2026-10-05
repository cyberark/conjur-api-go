package conjurapi

import (
	"errors"
	"fmt"
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
	MimeType    string            `json:"mime_type,omitempty"`
	Value       string            `json:"value,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Permissions []Permission      `json:"permissions,omitempty"`
}

type StaticSecretResponse struct {
	StaticSecret
	Permissions Permission `json:"permissions"`
}

func (c *ClientV2) CreateStaticSecretRequest(secret StaticSecret) (*http.Request, error) {
	err := secret.Validate()
	if err != nil {
		return nil, err
	}

	secretURL := makeRouterURL(c.config.ApplianceURL, "secrets/static").String()

	return newV2JSONRequest(http.MethodPost, secretURL, secret, v2APIHeader)
}

func (c *ClientV2) CreateStaticSecret(secret StaticSecret) (*StaticSecretResponse, error) {
	req, err := c.CreateStaticSecretRequest(secret)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[StaticSecretResponse](c, req)
}

func (c *ClientV2) GetStaticSecretDetailsRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	path := fmt.Sprintf("secrets/static/%s", identifier)

	secretURL := makeRouterURL(c.config.ApplianceURL, path).String()

	return newV2Request(http.MethodGet, secretURL, v2APIHeader)
}

func (c *ClientV2) GetStaticSecretDetails(identifier string) (*StaticSecretResponse, error) {
	req, err := c.GetStaticSecretDetailsRequest(identifier)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[StaticSecretResponse](c, req)
}

func (c *ClientV2) GetStaticSecretPermissionsRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an Identifier")
	}

	path := fmt.Sprintf("secrets/static/%s/permissions", identifier)

	secretURL := makeRouterURL(c.config.ApplianceURL, path).String()

	return newV2Request(http.MethodGet, secretURL, v2APIHeader)
}

func (c *ClientV2) GetStaticSecretPermissions(identifier string) (*PermissionResponse, error) {
	req, err := c.GetStaticSecretPermissionsRequest(identifier)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[PermissionResponse](c, req)
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
