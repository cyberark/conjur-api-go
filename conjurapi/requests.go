package conjurapi

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

func makeFullID(account, kind, id string) string {
	tokens := strings.SplitN(id, ":", 3)
	switch len(tokens) {
	case 1:
		tokens = []string{account, kind, tokens[0]}
	case 2:
		tokens = []string{account, tokens[0], tokens[1]}
	}
	// In the case where the ID has 3 tokens, we assume it's already fully-qualified.
	// However, we need to check if the first and second parts of the ID match the provided account and kind.
	// If not, we can assume they are actually part of the identifier, and we need to prepend the account and kind.
	// For example, a variable ID might be "foo:bar:baz". The fully-qualified ID is "account:variable:foo:bar:baz".
	// The one case we can't handle is if the variable ID matches what a fully-qualified ID would look like, such
	// as "account:variable:name", which could be either a fully-qualified ID or a partially-qualified ID.
	// In this case we assume it's a fully-qualified ID, and if the user wants to use a partially-qualified ID
	// they need to provide it as such ("account:variable:account:variable:name").
	if account != "" && account != tokens[0] || kind != "" && kind != tokens[1] {
		tokens = []string{account, kind, id}
	}
	return strings.Join(tokens, ":")
}

// parseID accepts as argument a resource ID and returns its components - account,
// resource kind, and identifier. The provided ID can either be fully- or
// partially-qualified. If the ID is only partially-qualified, the configured
// account will be returned.
//
// Examples:
// c.parseID("dev:user:alice")  =>  "dev", "user", "alice", nil
// c.parseID("user:alice")      =>  "dev", "user", "alice", nil
// c.parseID("prod:user:alice") => "prod", "user", "alice", nil
// c.parseID("malformed")       =>     "",     "",      "". error
func (c *Client) parseID(id string) (account, kind, identifier string, err error) {
	account, kind, identifier = unopinionatedParseID(id)
	if identifier == "" || kind == "" {
		return "", "", "", fmt.Errorf("Malformed ID '%s': must be fully- or partially-qualified, of form [<account>:]<kind>:<identifier>", id)
	}
	if account == "" {
		account = c.config.Account
	}
	return account, kind, identifier, nil
}

// parseIDandEnforceKind accepts as argument a resource ID and a kind, and returns
// the components - account, resource kind, and identifier - only if the provided
// resource matches the expected kind. If the ID is only partially-qualified, the
// configured account will be returned, and if the ID consists only of the
// identifier, the expected kind will be returned.
//
// Examples:
// c.parseID("dev:user:alice", "user")  =>  "dev", "user", "alice", nil
// c.parseID("user:alice", "user")      =>  "dev", "user", "alice", nil
// c.parseID("alice", "user")           =>  "dev", "user", "alice", nil
// c.parseID("prod:user:alice", "user") => "prod", "user", "alice", nil
// c.parseID("host:alice", "user")      =>     "",     "",      "", error
func (c *Client) parseIDandEnforceKind(id, enforcedKind string) (account, kind, identifier string, err error) {
	account, kind, identifier = unopinionatedParseID(id)
	if (identifier == "") || (kind != "" && kind != enforcedKind) {
		return "", "", "", fmt.Errorf("Malformed ID '%s', must represent a %s, of form [[<account>:]%s:]<identifier>", id, enforcedKind, enforcedKind)
	}
	if kind == "" {
		kind = enforcedKind
	}
	if account == "" {
		account = c.config.Account
	}
	return account, kind, identifier, nil
}

// unopinionatedParseID returns the components of the provided ID - account,
// resource kind, and identifier - without expectation on resource kind or
// account inclusion.
func unopinionatedParseID(id string) (account, kind, identifier string) {
	tokens := strings.SplitN(id, ":", 3)
	for len(tokens) < 3 {
		tokens = append([]string{""}, tokens...)
	}
	return tokens[0], tokens[1], tokens[2]
}

func (c *Client) SubmitRequest(req *http.Request) (resp *http.Response, err error) {
	err = c.createAuthRequest(req)
	if err != nil {
		return
	}
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	return c.submitRequestWithCustomAuth(req)
}

func (c *Client) submitRequestWithCustomAuth(req *http.Request) (resp *http.Response, err error) {
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}

	return
}

func (c *Client) WhoAmIRequest() (*http.Request, error) {
	return http.NewRequest(http.MethodGet, makeRouterURL(c.config.ApplianceURL, "whoami").String(), nil)
}

func (c *Client) LoginRequest(login string, password string) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), "login").String()

	req, err := http.NewRequest(http.MethodGet, authenticateURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(login, password)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (c *Client) AuthenticateRequest(loginPair authn.LoginPair) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), url.QueryEscape(loginPair.Login), "authenticate").String()

	req, err := http.NewRequest(http.MethodPost, authenticateURL, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func createJWTRequestBodyForAuthenticator(authnType, token string) (io.Reader, string) {
	switch authnType {
	case "iam":
		// IAM expects raw JSON in the body
		return bytes.NewReader([]byte(token)), "application/json"
	default:
		// Other authenticators expect url-encoded body
		formattedToken := fmt.Sprintf("jwt=%s", token)
		return strings.NewReader(formattedToken), "application/x-www-form-urlencoded"
	}
}

func (c *Client) JWTAuthenticateRequest(token, hostID string) (*http.Request, error) {
	var authenticateURL string
	var err error
	if hostID != "" {
		authenticateURL = makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), url.PathEscape(hostID), "authenticate").String()
	} else {
		authenticateURL = makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), "authenticate").String()
	}

	body, contentType := createJWTRequestBodyForAuthenticator(c.config.AuthnType, token)

	req, err := http.NewRequest(http.MethodPost, authenticateURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) ListOidcProvidersRequest() (*http.Request, error) {
	return http.NewRequest(http.MethodGet, c.oidcProvidersUrl(), nil)
}

// ServerInfoRequest crafts an HTTP request to Conjur's /info endpoint to retrieve
// This is only available in Secrets Manager Self-Hosted and will fail with a 404 error in Conjur OSS.
func (c *Client) ServerInfoRequest() (*http.Request, error) {
	return http.NewRequest(http.MethodGet, makeRouterURL(c.config.ApplianceURL, "info").String(), nil)
}

// RootRequest crafts an HTTP request to Conjur's root endpoint.
// In older versions of Conjur this will return an HTML page which will include
// some information about the server.
// In newer versions of Conjur this will return a JSON object with information about the server.
func (c *Client) RootRequest() (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, makeRouterURL(c.config.ApplianceURL).String(), nil)
	if err != nil {
		return nil, err
	}
	// Add the Accept header to the request to ensure that the server returns JSON, if available,
	// while still allowing for HTML responses in older versions of Conjur that do not support the
	// JSON response for the root endpoint.
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	req.Header.Add("Accept", "application/json, text/html")
	return req, nil
}

func (c *Client) OidcAuthenticateRequest(code, nonce, code_verifier string) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), "authenticate").withFormattedQuery("code=%s&nonce=%s&code_verifier=%s", code, nonce, code_verifier).String()

	req, err := http.NewRequest(http.MethodGet, authenticateURL, nil)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) OidcTokenAuthenticateRequest(token string) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(c.config.AuthnType, c.config.ServiceID), "authenticate").String()

	token = fmt.Sprintf("id_token=%s", token)
	req, err := http.NewRequest(http.MethodPost, authenticateURL, strings.NewReader(token))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) IAMAuthenticateRequest(signedHeaders []byte) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL("iam", c.config.ServiceID), url.QueryEscape("host/"+c.config.JWTHostID), "authenticate").String()

	body, contentType := createJWTRequestBodyForAuthenticator(c.config.AuthnType, string(signedHeaders))
	req, err := http.NewRequest("POST", authenticateURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) AzureAuthenticateRequest(azureToken string) (*http.Request, error) {
	return c.JWTAuthenticateRequest(azureToken, "host/"+c.config.JWTHostID)
}

func (c *Client) GCPAuthenticateRequest(gcpToken string) (*http.Request, error) {
	return c.JWTAuthenticateRequest(gcpToken, "")
}

// RotateAPIKeyRequest requires roleID argument to be at least partially-qualified
// ID of from [<account>:]<kind>:<identifier>.
func (c *Client) RotateAPIKeyRequest(roleID string) (*http.Request, error) {
	account, kind, identifier, err := c.parseID(roleID)
	if err != nil {
		return nil, err
	}
	roleID = fmt.Sprintf("%s:%s:%s", account, kind, identifier)

	// Always use the default authenticator for API key rotation
	rotateURL := makeRouterURL(c.authnURL("authn", ""), "api_key").withFormattedQuery("role=%s", roleID).String()

	return http.NewRequest(
		http.MethodPut,
		rotateURL,
		nil,
	)
}

func (c *Client) RotateCurrentUserAPIKeyRequest(login string, password string) (*http.Request, error) {
	return c.RotateCurrentRoleAPIKeyRequest(login, password)
}

func (c *Client) RotateCurrentRoleAPIKeyRequest(login string, password string) (*http.Request, error) {
	// Always use the default authenticator for API key rotation
	rotateUrl := makeRouterURL(c.authnURL("authn", ""), "api_key")

	req, err := http.NewRequest(
		http.MethodPut,
		rotateUrl.String(),
		nil,
	)

	if err != nil {
		return nil, err
	}

	// API key can only be rotated via basic auth, NOT using bearer token
	req.SetBasicAuth(login, password)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, nil
}

func (c *Client) ChangeUserPasswordRequest(username string, password string, newPassword string) (*http.Request, error) {
	passwordURL := makeRouterURL(c.config.ApplianceURL, "authn", c.config.Account, "password")

	req, err := http.NewRequest(
		http.MethodPut,
		passwordURL.String(),
		strings.NewReader(newPassword),
	)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	if err != nil {
		return nil, err
	}

	// Password can only be updated via basic auth, NOT using bearer token
	req.SetBasicAuth(username, password)

	return req, nil
}

// CheckPermissionRequest crafts an HTTP request to Conjur's /resource endpoint
// to check if the authenticated user has the given privilege on the given resourceID.
func (c *Client) CheckPermissionRequest(resourceID, privilege string) (*http.Request, error) {
	account, kind, id, err := c.parseID(resourceID)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("check=true&privilege=%s", url.QueryEscape(privilege))

	checkURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id)).withQuery(query).String()

	return http.NewRequest(
		http.MethodGet,
		checkURL,
		nil,
	)
}

// CheckPermissionForRoleRequest crafts an HTTP request to Conjur's /resource endpoint
// to check if a given role has the given privilege on the given resourceID.
func (c *Client) CheckPermissionForRoleRequest(resourceID, roleID, privilege string) (*http.Request, error) {
	account, kind, id, err := c.parseID(resourceID)
	if err != nil {
		return nil, err
	}

	roleAccount, roleKind, roleIdentifier, err := c.parseID(roleID)
	if err != nil {
		return nil, err
	}
	fullyQualifiedRoleID := strings.Join([]string{roleAccount, roleKind, roleIdentifier}, ":")

	query := fmt.Sprintf("check=true&privilege=%s&role=%s", url.QueryEscape(privilege), url.QueryEscape(fullyQualifiedRoleID))

	checkURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id)).withQuery(query).String()

	return http.NewRequest(
		http.MethodGet,
		checkURL,
		nil,
	)
}

func (c *Client) ResourceRequest(resourceID string) (*http.Request, error) {
	account, kind, id, err := c.parseID(resourceID)
	if err != nil {
		return nil, err
	}

	requestURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id))

	return http.NewRequest(
		http.MethodGet,
		requestURL.String(),
		nil,
	)
}

func (c *Client) resourcesRequest(filter *ResourceFilter, count bool) (*http.Request, error) {
	query := url.Values{}
	if count {
		query.Add("count", "true")
	}

	if filter != nil {
		if len(filter.Kind) > 0 {
			query.Add("kind", filter.Kind)
		}
		if len(filter.Search) > 0 {
			query.Add("search", filter.Search)
		}

		if filter.Limit != 0 {
			query.Add("limit", strconv.Itoa(filter.Limit))
		}

		if filter.Offset != 0 {
			query.Add("offset", strconv.Itoa(filter.Offset))
		}

		if len(filter.Role) > 0 {
			query.Add("acting_as", filter.Role)
		}
	}
	requestURL := makeRouterURL(c.resourcesURL(c.config.Account)).withQuery(query.Encode())

	return http.NewRequest(
		http.MethodGet,
		requestURL.String(),
		nil,
	)
}

func (c *Client) ResourcesRequest(filter *ResourceFilter) (*http.Request, error) {
	return c.resourcesRequest(filter, false)
}

func (c *Client) ResourcesCountRequest(filter *ResourceFilter) (*http.Request, error) {
	return c.resourcesRequest(filter, true)
}

func (c *Client) PermittedRolesRequest(resourceID string, privilege string) (*http.Request, error) {
	account, kind, id, err := c.parseID(resourceID)
	if err != nil {
		return nil, err
	}
	permittedRolesURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id)).withFormattedQuery("permitted_roles=true&privilege=%s", url.QueryEscape(privilege)).String()

	return http.NewRequest(
		http.MethodGet,
		permittedRolesURL,
		nil,
	)
}

func (c *Client) RoleRequest(roleID string) (*http.Request, error) {
	account, kind, id, err := c.parseID(roleID)
	if err != nil {
		return nil, err
	}
	roleURL := makeRouterURL(c.rolesURL(account), kind, url.QueryEscape(id))

	return http.NewRequest(
		http.MethodGet,
		roleURL.String(),
		nil,
	)
}

func (c *Client) RoleMembersRequest(roleID string) (*http.Request, error) {
	account, kind, id, err := c.parseID(roleID)
	if err != nil {
		return nil, err
	}
	roleMembersURL := makeRouterURL(c.rolesURL(account), kind, url.QueryEscape(id)).withFormattedQuery("members")

	return http.NewRequest(
		http.MethodGet,
		roleMembersURL.String(),
		nil,
	)
}

func (c *Client) RoleMembershipsRequest(roleID string) (*http.Request, error) {
	return c.RoleMembershipsRequestWithOptions(roleID, false)
}

// RoleMembershipsRequestWithOptions crafts an HTTP request to Conjur's /role endpoint
// allowing for either direct or all memberships to be returned.
func (c *Client) RoleMembershipsRequestWithOptions(roleID string, includeAll bool) (*http.Request, error) {
	account, kind, id, err := c.parseID(roleID)
	if err != nil {
		return nil, err
	}

	query := "memberships"
	if includeAll {
		query = "all"
	}

	roleMembershipsURL := makeRouterURL(c.rolesURL(account), kind, url.QueryEscape(id)).withFormattedQuery(query)

	return http.NewRequest(
		http.MethodGet,
		roleMembershipsURL.String(),
		nil,
	)
}

func (c *Client) LoadPolicyRequest(mode PolicyMode, policyID string, policy io.Reader, validate bool) (*http.Request, error) {
	fullPolicyID := makeFullID(c.config.Account, "policy", policyID)

	account, kind, id, err := c.parseID(fullPolicyID)
	if err != nil {
		return nil, err
	}

	routerUrl := makeRouterURL(
		c.policiesURL(account),
		kind,
		url.QueryEscape(id),
	)

	if validate {
		routerUrl = routerUrl.withQuery("dryRun=true")
	}

	policyURL := routerUrl.String()

	var method string
	switch mode {
	case PolicyModePost:
		method = http.MethodPost
	case PolicyModePatch:
		method = http.MethodPatch
	case PolicyModePut:
		method = http.MethodPut
	default:
		return nil, fmt.Errorf("Invalid PolicyMode: %d", mode)
	}

	return http.NewRequest(
		method,
		policyURL,
		policy,
	)
}

func (c *Client) fetchPolicyRequest(policyID string, returnJSON bool, policyTreeDepth uint, sizeLimit uint) (*http.Request, error) {
	fullPolicyID := makeFullID(c.config.Account, "policy", policyID)

	account, kind, id, err := c.parseID(fullPolicyID)
	if err != nil {
		return nil, err
	}

	routerUrl := makeRouterURL(
		c.policiesURL(account),
		kind,
		url.QueryEscape(id),
	)

	routerUrl = routerUrl.withFormattedQuery(
		"depth=%s&limit=%s",
		url.QueryEscape(strconv.Itoa(int(policyTreeDepth))),
		url.QueryEscape(strconv.Itoa(int(sizeLimit))),
	)
	policyURL := routerUrl.String()

	req, err := http.NewRequest(
		http.MethodGet,
		policyURL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	contentType := "application/x-yaml"
	if returnJSON {
		contentType = "application/json"
	}

	req.Header.Add("Content-Type", contentType)
	req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return req, err
}

func (c *Client) RetrieveBatchSecretsRequest(variableIDs []string, base64Flag bool) (*http.Request, error) {
	fullVariableIDs := []string{}
	for _, variableID := range variableIDs {
		fullVariableID := makeFullID(c.config.Account, "variable", variableID)
		fullVariableIDs = append(fullVariableIDs, fullVariableID)
	}

	request, err := http.NewRequest(
		http.MethodGet,
		c.batchVariableURL(fullVariableIDs),
		nil,
	)

	if err != nil {
		return nil, err
	}

	if base64Flag {
		request.Header.Add("Accept-Encoding", "base64")
	}

	return request, nil
}

func (c *Client) RetrieveSecretRequest(variableID string) (*http.Request, error) {
	fullVariableID := makeFullID(c.config.Account, "variable", variableID)

	variableURL, err := c.variableURL(fullVariableID)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(
		http.MethodGet,
		variableURL,
		nil,
	)
}

func (c *Client) RetrieveSecretWithVersionRequest(variableID string, version int) (*http.Request, error) {
	fullVariableID := makeFullID(c.config.Account, "variable", variableID)

	variableURL, err := c.variableWithVersionURL(fullVariableID, version)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(
		http.MethodGet,
		variableURL,
		nil,
	)
}

func (c *Client) AddSecretRequest(variableID, secretValue string) (*http.Request, error) {
	fullVariableID := makeFullID(c.config.Account, "variable", variableID)

	variableURL, err := c.variableURL(fullVariableID)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(
		http.MethodPost,
		variableURL,
		strings.NewReader(secretValue),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return request, nil
}

func (c *Client) CreateTokenRequest(body string) (*http.Request, error) {

	tokenURL := c.createTokenURL()
	request, err := http.NewRequest(
		http.MethodPost,
		tokenURL,
		strings.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	return request, nil

}

func (c *Client) DeleteTokenRequest(token string) (*http.Request, error) {
	tokenURL := c.createTokenURL() + "/" + token

	request, err := http.NewRequest(
		http.MethodDelete,
		tokenURL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
	return request, nil
}

func (c *Client) CreateHostRequest(body string, token string) (*http.Request, error) {
	hostURL := c.createHostURL()
	request, err := http.NewRequest(
		http.MethodPost,
		hostURL,
		strings.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Authorization", fmt.Sprintf("Token token=\"%s\"", token))
	request.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())

	return request, nil
}

func (c *Client) PublicKeysRequest(kind string, identifier string) (*http.Request, error) {
	publicKeysURL := makeRouterURL(c.config.ApplianceURL, "public_keys", c.config.Account, kind, identifier)
	return http.NewRequest(http.MethodGet, publicKeysURL.String(), nil)
}

func (c *Client) EnableAuthenticatorRequest(authenticatorType string, serviceID string, enabled bool) (*http.Request, error) {
	body := url.Values{}
	body.Set("enabled", strconv.FormatBool(enabled))

	request, err := http.NewRequest(
		http.MethodPatch,
		c.authnURL(authenticatorType, serviceID),
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return request, nil
}

func (c *Client) AuthenticatorStatusRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	statusURL := makeRouterURL(c.authnURL(authenticatorType, serviceID), "status").String()
	return http.NewRequest(http.MethodGet, statusURL, nil)
}

func (c *Client) createTokenURL() string {
	return makeRouterURL(c.config.ApplianceURL, "host_factory_tokens").String()
}

func (c *Client) createHostURL() string {
	return makeRouterURL(c.config.ApplianceURL, "host_factories/hosts").String()
}

func (c *Client) variableURL(variableID string) (string, error) {
	account, kind, id, err := c.parseID(variableID)
	if err != nil {
		return "", err
	}
	return makeRouterURL(c.secretsURL(account), kind, url.PathEscape(id)).String(), nil
}

func (c *Client) variableWithVersionURL(variableID string, version int) (string, error) {
	account, kind, id, err := c.parseID(variableID)
	if err != nil {
		return "", err
	}
	return makeRouterURL(c.secretsURL(account), kind, url.PathEscape(id)).
		withFormattedQuery("version=%d", version).String(), nil
}

func (c *Client) batchVariableURL(variableIDs []string) string {
	queryString := url.QueryEscape(strings.Join(variableIDs, ","))
	return makeRouterURL(c.globalSecretsURL()).withFormattedQuery("variable_ids=%s", queryString).String()
}

func (c *Client) authnURL(authenticatorType string, serviceID string) string {
	authnType := fmt.Sprintf("authn-%s", authenticatorType)

	if authenticatorType == "gcp" {
		return makeRouterURL(c.config.ApplianceURL, authnType, c.config.Account).String()
	}

	if authenticatorType == "cloud" {
		return makeRouterURL(c.config.ApplianceURL, "authn-oidc", serviceID, c.config.Account).String()
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.config.ApplianceURL, authnType, serviceID, c.config.Account).String()
	}

	// For the default authn service, the URL will be '/authn/<account>'
	return makeRouterURL(c.config.ApplianceURL, "authn", c.config.Account).String()
}

func (c *Client) oidcProvidersUrl() string {
	return makeRouterURL(c.config.ApplianceURL, "authn-oidc", c.config.Account, "providers").String()
}

func (c *Client) resourcesURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "resources", account).String()
}

func (c *Client) rolesURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "roles", account).String()
}

func (c *Client) secretsURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "secrets", account).String()
}

func (c *Client) globalSecretsURL() string {
	return makeRouterURL(c.config.ApplianceURL, "secrets").String()
}

func (c *Client) policiesURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "policies", account).String()
}
