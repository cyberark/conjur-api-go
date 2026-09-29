package conjurapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// LdapGroupMappingResponse represents the response for a single LDAP group mapping.
type LdapGroupMappingResponse struct {
	LdapGroup string   `json:"ldap_group"`
	Roles     []string `json:"roles"`
}

// LdapUserMappingResponse represents the response for a single LDAP user mapping.
type LdapUserMappingResponse struct {
	LdapUsername string   `json:"ldap_username"`
	Roles        []string `json:"roles"`
}

// LdapMappingListResponse represents a list of mapping keys.
type LdapMappingListResponse struct {
	Keys []string `json:"keys"`
}

const LdapMappingsMinVersion = "1.28.0"

// LdapCreateGroupMapping creates an LDAP group -> Conjur role mapping.
func (c *Client) LdapCreateGroupMapping(serviceID, groupName string, roles []string) (*LdapGroupMappingResponse, error) {
	req, err := c.LdapCreateGroupMappingRequest(serviceID, groupName, roles)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapGroupMappingResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapShowGroupMapping retrieves a single LDAP group mapping.
func (c *Client) LdapShowGroupMapping(serviceID, groupName string) (*LdapGroupMappingResponse, error) {
	req, err := c.LdapShowGroupMappingRequest(serviceID, groupName)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapGroupMappingResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapListGroupMappings lists all LDAP group mappings for a service.
func (c *Client) LdapListGroupMappings(serviceID string) (*LdapMappingListResponse, error) {
	req, err := c.LdapListGroupMappingsRequest(serviceID)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapMappingListResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapDeleteGroupMapping deletes an LDAP group mapping.
func (c *Client) LdapDeleteGroupMapping(serviceID, groupName string) error {
	req, err := c.LdapDeleteGroupMappingRequest(serviceID, groupName)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}

// LdapCreateUserMapping creates an LDAP user -> Conjur role mapping.
func (c *Client) LdapCreateUserMapping(serviceID, username string, roles []string) (*LdapUserMappingResponse, error) {
	req, err := c.LdapCreateUserMappingRequest(serviceID, username, roles)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapUserMappingResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapShowUserMapping retrieves a single LDAP user mapping.
func (c *Client) LdapShowUserMapping(serviceID, username string) (*LdapUserMappingResponse, error) {
	req, err := c.LdapShowUserMappingRequest(serviceID, username)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapUserMappingResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapListUserMappings lists all LDAP user mappings for a service.
func (c *Client) LdapListUserMappings(serviceID string) (*LdapMappingListResponse, error) {
	req, err := c.LdapListUserMappingsRequest(serviceID)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := LdapMappingListResponse{}
	return &obj, response.JSONResponse(resp, &obj)
}

// LdapDeleteUserMapping deletes an LDAP user mapping.
func (c *Client) LdapDeleteUserMapping(serviceID, username string) error {
	req, err := c.LdapDeleteUserMappingRequest(serviceID, username)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}

func (c *Client) ldapGroupMappingURL(serviceID, groupName string) string {
	return makeRouterURL(
		c.config.ApplianceURL,
		"authn-ldap", url.PathEscape(serviceID),
		c.config.Account,
		"groups", url.PathEscape(groupName),
	).String()
}

func (c *Client) ldapGroupMappingsURL(serviceID string) string {
	return makeRouterURL(
		c.config.ApplianceURL,
		"authn-ldap", url.PathEscape(serviceID),
		c.config.Account,
		"groups",
	).String()
}

func (c *Client) ldapUserMappingURL(serviceID, username string) string {
	return makeRouterURL(
		c.config.ApplianceURL,
		"authn-ldap", url.PathEscape(serviceID),
		c.config.Account,
		"users", url.PathEscape(username),
	).String()
}

func (c *Client) ldapUserMappingsURL(serviceID string) string {
	return makeRouterURL(
		c.config.ApplianceURL,
		"authn-ldap", url.PathEscape(serviceID),
		c.config.Account,
		"users",
	).String()
}

func ldapMappingBody(roles []string) string {
	body := struct {
		Roles []string `json:"roles"`
	}{Roles: roles}
	data, _ := json.Marshal(body)
	return string(data)
}

// LdapCreateGroupMappingRequest builds a POST request for creating a group mapping.
func (c *Client) LdapCreateGroupMappingRequest(serviceID, groupName string, roles []string) (*http.Request, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		c.ldapGroupMappingURL(serviceID, groupName),
		strings.NewReader(ldapMappingBody(roles)),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// LdapShowGroupMappingRequest builds a GET request for showing a group mapping.
func (c *Client) LdapShowGroupMappingRequest(serviceID, groupName string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, c.ldapGroupMappingURL(serviceID, groupName), nil)
}

// LdapListGroupMappingsRequest builds a GET request for listing group mappings.
func (c *Client) LdapListGroupMappingsRequest(serviceID string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, c.ldapGroupMappingsURL(serviceID), nil)
}

// LdapDeleteGroupMappingRequest builds a DELETE request for deleting a group mapping.
func (c *Client) LdapDeleteGroupMappingRequest(serviceID, groupName string) (*http.Request, error) {
	return http.NewRequest(http.MethodDelete, c.ldapGroupMappingURL(serviceID, groupName), nil)
}

// LdapCreateUserMappingRequest builds a POST request for creating a user mapping.
func (c *Client) LdapCreateUserMappingRequest(serviceID, username string, roles []string) (*http.Request, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		c.ldapUserMappingURL(serviceID, username),
		strings.NewReader(ldapMappingBody(roles)),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// LdapShowUserMappingRequest builds a GET request for showing a user mapping.
func (c *Client) LdapShowUserMappingRequest(serviceID, username string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, c.ldapUserMappingURL(serviceID, username), nil)
}

// LdapListUserMappingsRequest builds a GET request for listing user mappings.
func (c *Client) LdapListUserMappingsRequest(serviceID string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, c.ldapUserMappingsURL(serviceID), nil)
}

// LdapDeleteUserMappingRequest builds a DELETE request for deleting a user mapping.
func (c *Client) LdapDeleteUserMappingRequest(serviceID, username string) (*http.Request, error) {
	return http.NewRequest(http.MethodDelete, c.ldapUserMappingURL(serviceID, username), nil)
}
