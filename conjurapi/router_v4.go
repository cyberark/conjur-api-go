package conjurapi

import (
  "io"
  "fmt"
  "net/http"
  "net/url"
  "strings"

  "github.com/cyberark/conjur-api-go/conjurapi/authn"
)

type RouterV4 struct {
  Config *Config
}

func (self RouterV4) AuthenticateRequest(loginPair authn.LoginPair) (*http.Request, error) {
  authenticateUrl := fmt.Sprintf("%s/authn/users/%s/authenticate", self.Config.ApplianceURL, url.QueryEscape(loginPair.Login))

  req, err := http.NewRequest("POST", authenticateUrl, strings.NewReader(loginPair.APIKey))
  if err != nil {
    return nil, err
  }
  req.Header.Set("Content-Type", "text/plain")

  return req, nil
}

func (self RouterV4) RotateAPIKeyRequest(roleId string) (*http.Request, error) {
  tokens := strings.SplitN(roleId, ":", 3)
  if len(tokens) != 3 {
    return nil, fmt.Errorf("Role id '%s' must be fully qualified", roleId)
  }
  if tokens[0] != self.Config.Account {
    return nil, fmt.Errorf("Account of '%s' must match the configured account '%s'", roleId, self.Config.Account)
  }

  var username string
  switch tokens[1] {
  case "user":
    username = tokens[2]
  default:
    username = strings.Join([]string{ tokens[1], tokens[2] }, "/")
  }

  rotateUrl := fmt.Sprintf("%s/authn/users/api_key?id=%s", self.Config.ApplianceURL, username)

  return http.NewRequest(
    "PUT",
    rotateUrl,
    nil,
  )
}

func (self RouterV4) LoadPolicyRequest(policyId string, policy io.Reader) (*http.Request, error) {
  return nil, fmt.Errorf("LoadPolicy is not supported for Conjur V4")
}

func (self RouterV4) CheckPermissionRequest(resourceId, privilege string) (*http.Request, error) {
  tokens := strings.SplitN(resourceId, ":", 3)
  if len(tokens) != 3 {
    return nil, fmt.Errorf("Resource id '%s' must be fully qualified", resourceId)
  }
  checkUrl := fmt.Sprintf("%s/authz/%s/resources/%s/%s?check=true&privilege=%s", self.Config.ApplianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]), url.QueryEscape(privilege))

  return http.NewRequest(
    "GET",
    checkUrl,
    nil,
  )
}

func (self RouterV4) AddSecretRequest(variableId, secretValue string) (*http.Request, error) {
  return nil, fmt.Errorf("AddSecret is not supported for Conjur V4")
}

func (self RouterV4) RetrieveSecretRequest(variableIdentifier string) (*http.Request, error) {
  return http.NewRequest(
    "GET",
    self.variableURL(variableIdentifier),
    nil,
  )
}

func (self RouterV4) variableURL(variableIdentifier string) string {
  return fmt.Sprintf("%s/variables/%s/value", self.Config.ApplianceURL, url.QueryEscape(variableIdentifier))
}
