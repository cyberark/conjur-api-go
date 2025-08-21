package conjurapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const V2AcceptHeader = "application/x.secretsmgr.v2beta+json"

func (c *V2Client) CreateAuthenticatorRequest(authenticator *AuthenticatorBase) (*http.Request, error) {
	body, err := json.Marshal(authenticator)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator request: %w", err)
	}

	request, err := http.NewRequest(
		http.MethodPost,
		c.authenticatorsURL("", ""),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", V2AcceptHeader)

	return request, nil
}

func (c *V2Client) GetAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", V2AcceptHeader)

	return request, nil
}

func (c *V2Client) UpdateAuthenticatorRequest(authenticatorType string, serviceID string, enabled bool) (*http.Request, error) {
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator update request: %w", err)
	}

	request, err := http.NewRequest(
		http.MethodPatch,
		c.authenticatorsURL(authenticatorType, serviceID),
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", V2AcceptHeader)
	request.Header.Add("Content-Type", "application/json")
	return request, nil
}

func (c *V2Client) DeleteAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodDelete,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", V2AcceptHeader)

	return request, nil
}

func (c *V2Client) ListAuthenticatorsRequest() (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL("", ""),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", V2AcceptHeader)

	return request, nil
}

func (c *V2Client) authenticatorsURL(authenticatorType string, serviceID string) string {
	// If running against Conjur Cloud, the account is not used in the URL.
	account := c.client.config.Account
	if isConjurCloudURL(c.client.config.ApplianceURL) {
		account = ""
	}

	// TODO: validate GCP does not use service IDs and if it should be accessible via this API
	if authenticatorType == "gcp" {
		return makeRouterURL(c.client.config.ApplianceURL, "authenticators", account, authenticatorType).String()
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.client.config.ApplianceURL, "authenticators", account, authenticatorType, serviceID).String()
	}

	// For the default authenticators service endpoint
	return makeRouterURL(c.client.config.ApplianceURL, "authenticators", account).String()
}
