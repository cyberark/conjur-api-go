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

func (self RouterV4) LoadPolicyRequest(policyId string, policy io.Reader) (*http.Request, error) {
  return nil, fmt.Errorf("LoadPolicy is not supported for Conjur V4")
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
