package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type AuthenticatorBase struct {
	Type        string                 `json:"type"`
	Subtype     *string                `json:"subtype,omitempty"`
	Name        string                 `json:"name"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Owner       *AuthOwner             `json:"owner,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
}

type AuthenticatorResponse struct {
	AuthenticatorBase
	// Branch is the policy branch the authenticator is in. Only Self-Hosted
	// sends it.
	Branch string `json:"branch,omitempty"`
	// CreatedAt is when the authenticator was created. Only SaaS sends it.
	CreatedAt string `json:"created_at,omitempty"`
}

type AuthOwner struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type AuthenticatorListResponse struct {
	Authenticators []AuthenticatorResponse `json:"authenticators"`
	// Count is the number of authenticators before limit and offset. SaaS
	// ignores them for now, so there it's the length of Authenticators.
	Count int `json:"count"`
}

// AuthenticatorPatch is a partial V2 authenticator update; only set fields are sent.
type AuthenticatorPatch struct {
	Enabled     *bool                  `json:"enabled,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// AuthenticatorFilter carries pagination parameters for ListAuthenticators.
type AuthenticatorFilter struct {
	Limit  int
	Offset int
}

const AuthenticatorsMinVersion = MinVersion

// gcpAuthenticatorName is the V2 name of the GCP authenticator.
const gcpAuthenticatorName = "default"

// canonicalAuthnTypesV2 maps the v1 short type forms onto the V2 route vocabulary.
var canonicalAuthnTypesV2 = map[string]string{
	"iam":        "aws_iam",
	"authn-iam":  "aws_iam",
	"cert":       "certificate",
	"authn-cert": "certificate",
}

// Bool is a helper function to create a pointer to a boolean value.
func Bool(v bool) *bool { return &v }

// ParseAuthenticatorID splits a combined "authn-<type>/<name>" identifier into a
// V2 type and name; "authn-gcp" has no name.
func ParseAuthenticatorID(id string) (authenticatorType string, name string, err error) {
	if id == "" {
		return "", "", fmt.Errorf("authenticator identifier must not be empty")
	}

	if id == "authn-gcp" || id == "gcp" {
		return "gcp", "", nil
	}

	parts := strings.SplitN(id, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf(
			"invalid authenticator ID format: %s, expected format is 'authenticator_type/service_id'", id,
		)
	}

	authenticatorType = canonicalizeAuthenticatorTypeV2(parts[0])
	name = parts[1]
	return authenticatorType, name, nil
}

// CreateAuthenticator creates a new authenticator instance using the V2 API.
//
// The authenticated user must have create privileges on the conjur/authn-<type> policy.
func (c *ClientV2) CreateAuthenticator(authenticator *AuthenticatorBase) (*AuthenticatorResponse, error) {
	req, err := c.CreateAuthenticatorRequest(authenticator)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[AuthenticatorResponse](c, req)
}

// GetAuthenticator gets an existing authenticator instance using the V2 API.
//
// The authenticated user must have read privileges on the authenticator.
func (c *ClientV2) GetAuthenticator(authenticatorType string, authenticatorName string) (*AuthenticatorResponse, error) {
	req, err := c.GetAuthenticatorRequest(authenticatorType, authenticatorName)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[AuthenticatorResponse](c, req)
}

// UpdateAuthenticator applies a partial update to an existing authenticator using the V2 API.
//
// On Self-Hosted the V2 PATCH can only change enabled, so a patch that sets
// annotations or data, or doesn't set enabled, is refused before it is sent.
//
// The authenticated user must have update privileges on the authenticator.
func (c *ClientV2) UpdateAuthenticator(authenticatorType string, authenticatorName string, patch *AuthenticatorPatch) (*AuthenticatorResponse, error) {
	req, err := c.UpdateAuthenticatorRequest(authenticatorType, authenticatorName, patch)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[AuthenticatorResponse](c, req)
}

// SetAuthenticatorEnabledV2 enables or disables an authenticator using the V2 API.
func (c *ClientV2) SetAuthenticatorEnabledV2(authenticatorType string, authenticatorName string, enabled bool) (*AuthenticatorResponse, error) {
	return c.UpdateAuthenticator(authenticatorType, authenticatorName, &AuthenticatorPatch{Enabled: Bool(enabled)})
}

// DeleteAuthenticator deletes an existing authenticator instance using the V2 API.
//
// The authenticated user must have update privileges on the authenticator.
func (c *ClientV2) DeleteAuthenticator(authenticatorType string, authenticatorName string) error {
	req, err := c.DeleteAuthenticatorRequest(authenticatorType, authenticatorName)
	if err != nil {
		return err
	}

	return submitAndEmpty(c, req)
}

// ListAuthenticators gets a page of existing authenticators using the V2 API.
// filter may be nil. SaaS ignores limit and offset for now: it returns its
// whole list, at most 1000, and Count is the length of that list.
//
// The authenticated user must have read privileges on the authenticators.
func (c *ClientV2) ListAuthenticators(filter *AuthenticatorFilter) (*AuthenticatorListResponse, error) {
	req, err := c.ListAuthenticatorsRequest(filter)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[AuthenticatorListResponse](c, req)
}

func (c *ClientV2) CreateAuthenticatorRequest(authenticator *AuthenticatorBase) (*http.Request, error) {
	authenticatorsURL, err := c.authenticatorsURL("", "")
	if err != nil {
		return nil, err
	}

	request, err := newV2JSONRequest(http.MethodPost, authenticatorsURL, authenticator, v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator request: %w", err)
	}
	return request, nil
}

func (c *ClientV2) GetAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	authenticatorURL, err := c.authenticatorsURL(authenticatorType, serviceID)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodGet, authenticatorURL, v2APIHeaderBeta)
}

// UpdateAuthenticatorRequest builds a V2 PATCH request with the fields set on patch.
func (c *ClientV2) UpdateAuthenticatorRequest(authenticatorType string, serviceID string, patch *AuthenticatorPatch) (*http.Request, error) {
	if patch == nil {
		patch = &AuthenticatorPatch{}
	}
	if !c.config.IsSaaS() {
		if err := patch.checkSelfHosted(); err != nil {
			return nil, err
		}
	}

	authenticatorURL, err := c.authenticatorsURL(authenticatorType, serviceID)
	if err != nil {
		return nil, err
	}

	request, err := newV2JSONRequest(
		http.MethodPatch,
		authenticatorURL,
		patch,
		v2APIHeaderBeta,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator update request: %w", err)
	}
	return request, nil
}

func (c *ClientV2) DeleteAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	authenticatorURL, err := c.authenticatorsURL(authenticatorType, serviceID)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodDelete, authenticatorURL, v2APIHeaderBeta)
}

func (c *ClientV2) ListAuthenticatorsRequest(filter *AuthenticatorFilter) (*http.Request, error) {
	baseURL, err := c.authenticatorsURL("", "")
	if err != nil {
		return nil, err
	}
	query := url.Values{}

	if filter != nil {
		if filter.Limit > 0 {
			query.Add("limit", fmt.Sprintf("%d", filter.Limit))
		}
		if filter.Offset > 0 {
			query.Add("offset", fmt.Sprintf("%d", filter.Offset))
		}
	}

	requestURL := baseURL
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", baseURL, encoded)
	}

	return newV2Request(http.MethodGet, requestURL, v2APIHeaderBeta)
}

// checkSelfHosted reports why a Self-Hosted server would refuse p. Its V2
// PATCH only switches an authenticator on or off: it requires "enabled" and
// answers 422 to anything else.
func (p *AuthenticatorPatch) checkSelfHosted() error {
	var others []string
	if len(p.Annotations) > 0 {
		others = append(others, "annotations")
	}
	if len(p.Data) > 0 {
		others = append(others, "data")
	}
	if len(others) > 0 {
		return fmt.Errorf(`Updating an authenticator's %s is not supported in Idira Secrets Manager/Conjur OSS; only "enabled" can be changed`,
			strings.Join(others, " and "))
	}
	if p.Enabled == nil {
		return errors.New(`An authenticator update must set "enabled" in Idira Secrets Manager/Conjur OSS, the only setting it can change`)
	}
	return nil
}

func canonicalizeAuthenticatorTypeV2(authenticatorType string) string {
	t := strings.TrimPrefix(authenticatorType, "authn-")
	if mapped, ok := canonicalAuthnTypesV2[authenticatorType]; ok {
		return mapped
	}
	if mapped, ok := canonicalAuthnTypesV2[t]; ok {
		return mapped
	}
	return t
}

func (c *ClientV2) authenticatorsURL(authenticatorType string, serviceID string) (string, error) {
	// If running against Secrets Manager SaaS, the account is not used in the URL.
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}

	// The GCP authenticator has no name of its own, and both servers route it
	// as "default".
	if authenticatorType == "gcp" && serviceID == "" {
		serviceID = gcpAuthenticatorName
	}

	escapedType, escapedServiceID, err := escapeAuthenticatorPath(authenticatorType, serviceID)
	if err != nil {
		return "", err
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, escapedType, escapedServiceID).String(), nil
	}

	// For the default authenticators service endpoint
	return makeRouterURL(c.config.ApplianceURL, "authenticators", account).String(), nil
}

// escapeAuthenticatorPath escapes the type as one segment and each segment of
// the name, rejecting empty, "." and ".." ones. Empty values pass through.
func escapeAuthenticatorPath(authenticatorType string, name string) (string, string, error) {
	escapedType := ""
	if authenticatorType != "" {
		segments, err := escapePathSegments("Authenticator type", []string{authenticatorType})
		if err != nil {
			return "", "", err
		}
		escapedType = segments[0]
	}

	escapedName := ""
	if name != "" {
		segments, err := escapePathSegments("Authenticator name", strings.Split(name, "/"))
		if err != nil {
			return "", "", err
		}
		escapedName = strings.Join(segments, "/")
	}

	return escapedType, escapedName, nil
}
