package conjurapi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/sirupsen/logrus"
)

type RouterV4 struct {
	Config *Config
}

func (r RouterV4) AuthenticateRequest(loginPair authn.LoginPair) (*http.Request, error) {
	authenticateURL := fmt.Sprintf("%s/authn/users/%s/authenticate", r.Config.ApplianceURL, url.QueryEscape(loginPair.Login))

	req, err := http.NewRequest("POST", authenticateURL, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (r RouterV4) RotateAPIKeyRequest(roleID string) (*http.Request, error) {
	tokens := strings.SplitN(roleID, ":", 3)
	if len(tokens) != 3 {
		return nil, fmt.Errorf("Role id '%s' must be fully qualified", roleID)
	}
	if tokens[0] != r.Config.Account {
		return nil, fmt.Errorf("Account of '%s' must match the configured account '%s'", roleID, r.Config.Account)
	}

	var username string
	switch tokens[1] {
	case "user":
		username = tokens[2]
	default:
		username = strings.Join([]string{tokens[1], tokens[2]}, "/")
	}

	rotateURL := fmt.Sprintf("%s/authn/users/api_key?id=%s", r.Config.ApplianceURL, username)

	return http.NewRequest(
		"PUT",
		rotateURL,
		nil,
	)
}

func (r RouterV4) LoadPolicyRequest(mode PolicyMode, policyID string, policy io.Reader) (*http.Request, error) {
	return nil, fmt.Errorf("LoadPolicy is not supported for Conjur V4")
}

func (r RouterV4) ResourceRequest(resourceID string) (*http.Request, error) {
	logrus.Panic("ResourceRequest not implemented yet")
	return nil, nil
}

func (r RouterV4) ResourcesRequest(filter *ResourceFilter) (*http.Request, error) {
	logrus.Panic("ResourcesRequest not implemented yet")
	return nil, nil
}

func (r RouterV4) CheckPermissionRequest(resourceID, privilege string) (*http.Request, error) {
	tokens := strings.SplitN(resourceID, ":", 3)
	if len(tokens) != 3 {
		return nil, fmt.Errorf("Resource id '%s' must be fully qualified", resourceID)
	}
	checkURL := fmt.Sprintf("%s/authz/%s/resources/%s/%s?check=true&privilege=%s", r.Config.ApplianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]), url.QueryEscape(privilege))

	return http.NewRequest(
		"GET",
		checkURL,
		nil,
	)
}

func (r RouterV4) AddSecretRequest(variableIDentifier, secretValue string) (*http.Request, error) {
	return nil, fmt.Errorf("AddSecret is not supported for Conjur V4")
}

func (r RouterV4) RetrieveBatchSecretsRequest(variableIDs []string) (*http.Request, error) {
	return http.NewRequest(
		"GET",
		r.batchVariableURL(variableIDs),
		nil,
	)
}

func (r RouterV4) RetrieveSecretRequest(variableIDentifier string) (*http.Request, error) {
	return http.NewRequest(
		"GET",
		r.variableURL(variableIDentifier),
		nil,
	)
}

func (r RouterV4) variableURL(variableIDentifier string) string {
	return fmt.Sprintf("%s/variables/%s/value", r.Config.ApplianceURL, url.QueryEscape(variableIDentifier))
}

func (r RouterV4) batchVariableURL(variableIDs []string) string {
	queryString := url.QueryEscape(strings.Join(variableIDs, ","))
	return fmt.Sprintf("%s/variables/values?vars=%s", r.Config.ApplianceURL, queryString)
}
