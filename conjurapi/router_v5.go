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
	authenticateURL := fmt.Sprintf("%s/authn/%s/%s/authenticate", r.Config.ApplianceURL, r.Config.Account, url.QueryEscape(loginPair.Login))

	req, err := http.NewRequest("POST", authenticateURL, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (r RouterV5) RotateAPIKeyRequest(roleID string) (*http.Request, error) {
	rotateURL := fmt.Sprintf("%s/authn/%s/api_key?role=%s", r.Config.ApplianceURL, r.Config.Account, roleID)

	return http.NewRequest(
		"PUT",
		rotateURL,
		nil,
	)
}

func (r RouterV5) CheckPermissionRequest(resourceID, privilege string) (*http.Request, error) {
	tokens := strings.SplitN(resourceID, ":", 3)
	if len(tokens) != 3 {
		return nil, fmt.Errorf("Resource id '%s' must be fully qualified", resourceID)
	}
	checkURL := fmt.Sprintf("%s/resources/%s/%s/%s?check=true&privilege=%s", r.Config.ApplianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]), url.QueryEscape(privilege))

	return http.NewRequest(
		"GET",
		checkURL,
		nil,
	)
}

func (r RouterV5) LoadPolicyRequest(mode PolicyMode, policyID string, policy io.Reader) (*http.Request, error) {
	policyID = makeFullId(r.Config.Account, "policy", policyID)

	tokens := strings.SplitN(policyID, ":", 3)
	policyURL := fmt.Sprintf("%s/policies/%s/%s/%s", r.Config.ApplianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]))

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

func (r RouterV5) RetrieveSecretRequest(variableID string) (*http.Request, error) {
	variableID = makeFullId(r.Config.Account, "variable", variableID)

	return http.NewRequest(
		"GET",
		r.variableURL(variableID),
		nil,
	)
}

func (r RouterV5) AddSecretRequest(variableID, secretValue string) (*http.Request, error) {
	variableID = makeFullId(r.Config.Account, "variable", variableID)

	return http.NewRequest(
		"POST",
		r.variableURL(variableID),
		strings.NewReader(secretValue),
	)
}

func (r RouterV5) variableURL(variableID string) string {
	tokens := strings.SplitN(variableID, ":", 3)
	return fmt.Sprintf("%s/secrets/%s/%s/%s", r.Config.ApplianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]))
}
