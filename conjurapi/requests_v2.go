package conjurapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const v2APIHeaderBeta string = "application/x.secretsmgr.v2beta+json"
const v2APIHeader string = "application/x.secretsmgr.v2+json"
const v2APIOutgoingHeaderID string = "Accept"
const v2APIIncomingHeaderID string = "Content-Type"

func (c *ClientV2) CreateAuthenticatorRequest(authenticator *AuthenticatorBase) (*http.Request, error) {
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
	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) GetAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) UpdateAuthenticatorRequest(authenticatorType string, serviceID string, enabled bool) (*http.Request, error) {
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

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	request.Header.Add("Content-Type", "application/json")
	return request, nil
}

func (c *ClientV2) DeleteAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodDelete,
		c.authenticatorsURL(authenticatorType, serviceID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) ListAuthenticatorsRequest() (*http.Request, error) {
	request, err := http.NewRequest(
		http.MethodGet,
		c.authenticatorsURL("", ""),
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

	return request, nil
}

func (c *ClientV2) authenticatorsURL(authenticatorType string, serviceID string) string {
	// If running against Secrets Manager SaaS, the account is not used in the URL.
	account := c.config.Account
	if isConjurCloudURL(c.config.ApplianceURL) {
		account = ""
	}

	// TODO: validate GCP does not use service IDs and if it should be accessible via this API
	if authenticatorType == "gcp" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType).String()
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType, serviceID).String()
	}

	// For the default authenticators service endpoint
	return makeRouterURL(c.config.ApplianceURL, "authenticators", account).String()
}
