package conjurapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// Issuer defines the JSON data structure used with the Conjur API
type Issuer struct {
	ID string `json:"id"`
	Type string `json:"type"`
	MaxTTL int `json:"max_ttl"`
	Data map[string]interface{} `json:"data"`
	CreatedAt string `json:"created_at,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"`
}

// CreateIssuer creates a new Issuer in Conjur
func (c *Client) CreateIssuer(issuer Issuer) (created Issuer, err error) {
	req, err := c.createIssuerRequest(issuer)
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

	err = json.Unmarshal(data, &created)
	return
}

// DeleteIssuer deletes an existing Issuer in Conjur
func (c *Client) DeleteIssuer(issuerID string, keepSecrets bool) (err error) {
	req, err := c.deleteIssuerRequest(issuerID, keepSecrets)
	if err != nil {
		return
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return
	}

	err = response.EmptyResponse(resp)
	return
}

// Issuer retrieves an existing Issuer with the given ID
func (c *Client) Issuer(issuerID string) (issuer Issuer, err error) {
	req, err := c.issuerRequest(issuerID)
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

	err = json.Unmarshal(data, &issuer)
	return
}

func (c *Client) createIssuerRequest(issuer Issuer) (*http.Request, error) {
	issuersURL := makeRouterURL(c.issuersURL(c.config.Account))

	issuerJSON, err := json.Marshal(issuer)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		issuersURL.String(),
		bytes.NewReader(issuerJSON),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (c *Client) deleteIssuerRequest(issuerID string, keepSecrets bool) (*http.Request, error) {
	issuerURL := makeRouterURL(
		c.issuersURL(c.config.Account),
		url.QueryEscape(issuerID),
	).withFormattedQuery("keep_secrets=%t", keepSecrets)

	req, err := http.NewRequest("DELETE", issuerURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) issuerRequest(issuerID string) (*http.Request, error) {
	issuerURL := makeRouterURL(
		c.issuersURL(c.config.Account),
		url.QueryEscape(issuerID),
	)

	req, err := http.NewRequest("GET", issuerURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) issuersURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "issuers", account).String()
}
