package conjurapi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

type RouterV5 struct {
	Config *Config
}

func (r RouterV5) AuthenticateRequest(loginPair authn.LoginPair) (*http.Request, error) {
	authenticateURL := makeRouterURL(r.authnURL(), url.QueryEscape(loginPair.Login), "authenticate").String()

	req, err := http.NewRequest("POST", authenticateURL, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (r RouterV5) RotateAPIKeyRequest(roleID string) (*http.Request, error) {
	rotateURL := makeRouterURL(r.authnURL(), "api_key").withQuery("role=%s", roleID).String()

	return http.NewRequest(
		"PUT",
		rotateURL,
		nil,
	)
}

func (r RouterV5) CheckPermissionRequest(resourceID, privilege string) (*http.Request, error) {
	account, kind, id, err := parseID(resourceID)
	if err != nil {
		return nil, err
	}
	checkURL := makeRouterURL(r.resourcesURL(account), kind, url.QueryEscape(id)).withQuery("check=true&privilege=%s", url.QueryEscape(privilege)).String()

	return http.NewRequest(
		"GET",
		checkURL,
		nil,
	)
}

func (r RouterV5) ResourceRequest(resourceID string) (*http.Request, error) {
	account, kind, id, err := parseID(resourceID)
	if err != nil {
		return nil, err
	}

	requestURL := makeRouterURL(r.resourcesURL(account), kind, url.QueryEscape(id))

	return http.NewRequest(
		"GET",
		requestURL.String(),
		nil,
	)
}

func (r RouterV5) ResourcesRequest(filter *ResourceFilter) (*http.Request, error) {
	var query []string
	if filter != nil {
		if filter.Kind != "" {
			query = append(query, fmt.Sprintf("kind=%s", url.QueryEscape(filter.Kind)))
		}
	}

	requestURL := makeRouterURL(r.resourcesURL(r.Config.Account)).withQuery(strings.Join(query, "&"))

	return http.NewRequest(
		"GET",
		requestURL.String(),
		nil,
	)
}

func (r RouterV5) LoadPolicyRequest(mode PolicyMode, policyID string, policy io.Reader) (*http.Request, error) {
	policyID = makeFullId(r.Config.Account, "policy", policyID)

	account, kind, id, err := parseID(policyID)
	if err != nil {
		return nil, err
	}
	policyURL := makeRouterURL(r.policiesURL(account), kind, url.QueryEscape(id)).String()

	var method string
	switch mode {
	case PolicyModePost:
		method = "POST"
	case PolicyModePatch:
		method = "PATCH"
	case PolicyModePut:
		method = "PUT"
	default:
		return nil, fmt.Errorf("Invalid PolicyMode : %d", mode)
	}

	return http.NewRequest(
		method,
		policyURL,
		policy,
	)
}

func (r RouterV5) RetrieveBatchSecretsRequest(variableIDs []string) (*http.Request, error) {
	fullVariableIDs := []string{}
	for _, variable := range variableIDs {
		variableID := makeFullId(r.Config.Account, "variable", variable)
		fullVariableIDs = append(fullVariableIDs, variableID)
	}

	return http.NewRequest(
		"GET",
		r.batchVariableURL(fullVariableIDs),
		nil,
	)
}

func (r RouterV5) RetrieveSecretRequest(variableID string) (*http.Request, error) {
	variableID = makeFullId(r.Config.Account, "variable", variableID)

	variableURL, err := r.variableURL(variableID)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(
		"GET",
		variableURL,
		nil,
	)
}

func (r RouterV5) AddSecretRequest(variableID, secretValue string) (*http.Request, error) {
	variableID = makeFullId(r.Config.Account, "variable", variableID)

	variableURL, err := r.variableURL(variableID)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(
		"POST",
		variableURL,
		strings.NewReader(secretValue),
	)
}

func (r RouterV5) variableURL(variableID string) (string, error) {
	account, kind, id, err := parseID(variableID)
	if err != nil {
		return "", err
	}
	return makeRouterURL(r.secretsURL(account), kind, url.QueryEscape(id)).String(), nil
}

func (r RouterV5) batchVariableURL(variableIDs []string) string {
	queryString := url.QueryEscape(strings.Join(variableIDs, ","))
	return makeRouterURL(r.globalSecretsURL()).withQuery("variable_ids=%s", queryString).String()
}

func (r RouterV5) authnURL() string {
	return makeRouterURL(r.Config.ApplianceURL, "authn", r.Config.Account).String()
}

func (r RouterV5) resourcesURL(account string) string {
	return makeRouterURL(r.Config.ApplianceURL, "resources", account).String()
}

func (r RouterV5) secretsURL(account string) string {
	return makeRouterURL(r.Config.ApplianceURL, "secrets", account).String()
}

func (r RouterV5) globalSecretsURL() string {
	return makeRouterURL(r.Config.ApplianceURL, "secrets").String()
}

func (r RouterV5) policiesURL(account string) string {
	return makeRouterURL(r.Config.ApplianceURL, "policies", account).String()
}
