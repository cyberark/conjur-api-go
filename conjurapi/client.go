package conjurapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bgentry/go-netrc/netrc"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type Authenticator interface {
	RefreshToken() ([]byte, error)
	NeedsTokenRefresh() bool
}

type Client struct {
	config        Config
	authToken     *authn.AuthnToken
	httpClient    *http.Client
	authenticator Authenticator
}

func NewClientFromKey(config Config, loginPair authn.LoginPair) (*Client, error) {
	authenticator := &authn.APIKeyAuthenticator{
		LoginPair: loginPair,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	authenticator.Authenticate = client.Authenticate
	return client, err
}

// ReadResponseBody fully reads a response and closes it.
func ReadResponseBody(response io.ReadCloser) ([]byte, error) {
	defer response.Close()
	return ioutil.ReadAll(response)
}

func NewClientFromToken(config Config, token string) (*Client, error) {
	return newClientWithAuthenticator(
		config,
		&authn.TokenAuthenticator{token},
	)
}

func NewClientFromTokenFile(config Config, tokenFile string) (*Client, error) {
	return newClientWithAuthenticator(
		config,
		&authn.TokenFileAuthenticator{
			TokenFile:   tokenFile,
			MaxWaitTime: -1,
		},
	)
}

func LoginPairFromEnv() (*authn.LoginPair, error) {
	return &authn.LoginPair{
		Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
		APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
	}, nil
}

func LoginPairFromNetRC(config Config) (*authn.LoginPair, error) {
	if config.NetRCPath == "" {
		config.NetRCPath = os.ExpandEnv("$HOME/.netrc")
	}

	rc, err := netrc.ParseFile(config.NetRCPath)
	if err != nil {
		return nil, err
	}

	m := rc.FindMachine(config.ApplianceURL + "/authn")

	if m == nil {
		return nil, fmt.Errorf("No credentials found in NetRCPath")
	}

	return &authn.LoginPair{Login: m.Login, APIKey: m.Password}, nil
}

// TODO: Create a version of this function for creating an authenticator from environment
func NewClientFromEnvironment(config Config) (*Client, error) {
	err := config.validate()

	if err != nil {
		return nil, err
	}

	authnTokenFile := os.Getenv("CONJUR_AUTHN_TOKEN_FILE")
	if authnTokenFile != "" {
		return NewClientFromTokenFile(config, authnTokenFile)
	}

	authnToken := os.Getenv("CONJUR_AUTHN_TOKEN")
	if authnToken != "" {
		return NewClientFromToken(config, authnToken)
	}

	authnJwtServiceID := os.Getenv("CONJUR_AUTHN_JWT_SERVICE_ID")
	if authnJwtServiceID != "" {

		jwtTokenPath := os.Getenv("JWT_TOKEN_PATH")
		if jwtTokenPath == "" {
			jwtTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}

		jwtToken, err := ioutil.ReadFile(jwtTokenPath)
		if err != nil {
			return nil, err
		}
		jwtTokenString := fmt.Sprintf("jwt=%s", string(jwtToken))

		var httpClient *http.Client
		if config.IsHttps() {
			cert, err := config.ReadSSLCert()
			if err != nil {
				return nil, err
			}
			httpClient, err = newHTTPSClient(cert)
			if err != nil {
				return nil, err
			}

		} else {
			httpClient = &http.Client{Timeout: time.Second * 10}
		}

		authnJwtHostID := os.Getenv("CONJUR_AUTHN_JWT_HOST_ID")
		authnJwtUrl := ""
		if authnJwtHostID != "" {
			authnJwtUrl = makeRouterURL(config.ApplianceURL, "authn-jwt", authnJwtServiceID, config.Account, url.PathEscape(authnJwtHostID), "authenticate").String()
		} else {
			authnJwtUrl = makeRouterURL(config.ApplianceURL, "authn-jwt", authnJwtServiceID, config.Account, "authenticate").String()
		}

		req, err := http.NewRequest("POST", authnJwtUrl, strings.NewReader(jwtTokenString))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return NewClientFromToken(config, string(body))
	}

	loginPair, err := LoginPairFromEnv()
	if err == nil && loginPair.Login != "" && loginPair.APIKey != "" {
		return NewClientFromKey(config, *loginPair)
	}

	loginPair, err = LoginPairFromNetRC(config)
	if err == nil && loginPair.Login != "" && loginPair.APIKey != "" {
		return NewClientFromKey(config, *loginPair)
	}

	return nil, fmt.Errorf("Environment variables and machine identity files satisfying at least one authentication strategy must be present!")
}

func (c *Client) GetAuthenticator() Authenticator {
	return c.authenticator
}

func (c *Client) SetAuthenticator(authenticator Authenticator) {
	c.authenticator = authenticator
}

func (c *Client) GetHttpClient() *http.Client {
	return c.httpClient
}

func (c *Client) SetHttpClient(httpClient *http.Client) {
	c.httpClient = httpClient
}

func (c *Client) GetConfig() Config {
	return c.config
}

func (c *Client) SubmitRequest(req *http.Request) (resp *http.Response, err error) {
	err = c.createAuthRequest(req)
	if err != nil {
		return
	}

	logging.ApiLog.Debugf("req: %+v\n", req)
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return
	}

	return
}

func (c *Client) WhoAmIRequest() (*http.Request, error) {
	return http.NewRequest("GET", makeRouterURL(c.config.ApplianceURL, "whoami").String(), nil)
}

func (c *Client) LoginRequest(loginPair authn.LoginPair) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(), "login").String()

	req, err := http.NewRequest("GET", authenticateURL, nil)
	req.SetBasicAuth(loginPair.Login, loginPair.APIKey)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (c *Client) AuthenticateRequest(loginPair authn.LoginPair) (*http.Request, error) {
	authenticateURL := makeRouterURL(c.authnURL(), url.QueryEscape(loginPair.Login), "authenticate").String()

	req, err := http.NewRequest("POST", authenticateURL, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func (c *Client) RotateAPIKeyRequest(roleID string) (*http.Request, error) {
	account, _, _, err := parseID(roleID)
	if err != nil {
		return nil, err
	}
	if account != c.config.Account {
		return nil, fmt.Errorf("Account of '%s' must match the configured account '%s'", roleID, c.config.Account)
	}

	rotateURL := makeRouterURL(c.authnURL(), "api_key").withFormattedQuery("role=%s", roleID).String()

	return http.NewRequest(
		"PUT",
		rotateURL,
		nil,
	)
}

func (c *Client) CheckPermissionRequest(resourceID string, privilege string) (*http.Request, error) {
	account, kind, id, err := parseID(resourceID)
	if err != nil {
		return nil, err
	}
	checkURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id)).withFormattedQuery("check=true&privilege=%s", url.QueryEscape(privilege)).String()

	return http.NewRequest(
		"GET",
		checkURL,
		nil,
	)
}

func (c *Client) ResourceRequest(resourceID string) (*http.Request, error) {
	account, kind, id, err := parseID(resourceID)
	if err != nil {
		return nil, err
	}

	requestURL := makeRouterURL(c.resourcesURL(account), kind, url.QueryEscape(id))

	return http.NewRequest(
		"GET",
		requestURL.String(),
		nil,
	)
}

func (c *Client) ResourcesRequest(filter *ResourceFilter) (*http.Request, error) {
	query := url.Values{}

	if filter != nil {
		if filter.Kind != "" {
			query.Add("kind", filter.Kind)
		}
		if filter.Search != "" {
			query.Add("search", filter.Search)
		}

		if filter.Limit != 0 {
			query.Add("limit", strconv.Itoa(filter.Limit))
		}

		if filter.Offset != 0 {
			query.Add("offset", strconv.Itoa(filter.Offset))
		}
	}

	requestURL := makeRouterURL(c.resourcesURL(c.config.Account)).withQuery(query.Encode())

	return http.NewRequest(
		"GET",
		requestURL.String(),
		nil,
	)
}

func (c *Client) LoadPolicyRequest(mode PolicyMode, policyID string, policy io.Reader) (*http.Request, error) {
	fullPolicyID := makeFullId(c.config.Account, "policy", policyID)

	account, kind, id, err := parseID(fullPolicyID)
	if err != nil {
		return nil, err
	}
	policyURL := makeRouterURL(c.policiesURL(account), kind, url.QueryEscape(id)).String()

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

func (c *Client) RetrieveBatchSecretsRequest(variableIDs []string, base64Flag bool) (*http.Request, error) {
	fullVariableIDs := []string{}
	for _, variableID := range variableIDs {
		fullVariableID := makeFullId(c.config.Account, "variable", variableID)
		fullVariableIDs = append(fullVariableIDs, fullVariableID)
	}

	request, err := http.NewRequest(
		"GET",
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
	fullVariableID := makeFullId(c.config.Account, "variable", variableID)

	variableURL, err := c.variableURL(fullVariableID)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(
		"GET",
		variableURL,
		nil,
	)
}

func (c *Client) AddSecretRequest(variableID, secretValue string) (*http.Request, error) {
	fullVariableID := makeFullId(c.config.Account, "variable", variableID)

	variableURL, err := c.variableURL(fullVariableID)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(
		"POST",
		variableURL,
		strings.NewReader(secretValue),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return request, nil
}

func (c *Client) variableURL(variableID string) (string, error) {
	account, kind, id, err := parseID(variableID)
	if err != nil {
		return "", err
	}
	return makeRouterURL(c.secretsURL(account), kind, url.PathEscape(id)).String(), nil
}

func (c *Client) batchVariableURL(variableIDs []string) string {
	queryString := url.QueryEscape(strings.Join(variableIDs, ","))
	return makeRouterURL(c.globalSecretsURL()).withFormattedQuery("variable_ids=%s", queryString).String()
}

func (c *Client) authnURL() string {
	return makeRouterURL(c.config.ApplianceURL, "authn", c.config.Account).String()
}

func (c *Client) resourcesURL(account string) string {
	return makeRouterURL(c.config.ApplianceURL, "resources", account).String()
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

func makeFullId(account, kind, id string) string {
	tokens := strings.SplitN(id, ":", 3)
	switch len(tokens) {
	case 1:
		tokens = []string{account, kind, tokens[0]}
	case 2:
		tokens = []string{account, tokens[0], tokens[1]}
	}
	return strings.Join(tokens, ":")
}

func parseID(fullID string) (account, kind, id string, err error) {
	tokens := strings.SplitN(fullID, ":", 3)
	if len(tokens) != 3 {
		err = fmt.Errorf("Id '%s' must be fully qualified", fullID)
		return
	}
	return tokens[0], tokens[1], tokens[2], nil
}

func NewClient(config Config) (*Client, error) {
	var (
		err error
	)

	err = config.validate()

	if err != nil {
		return nil, err
	}

	var httpClient *http.Client

	if config.IsHttps() {
		cert, err := config.ReadSSLCert()
		if err != nil {
			return nil, err
		}
		httpClient, err = newHTTPSClient(cert)
		if err != nil {
			return nil, err
		}
	} else {
		httpClient = &http.Client{Timeout: time.Second * 10}
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}, nil
}

func newClientWithAuthenticator(config Config, authenticator Authenticator) (*Client, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}

	client.authenticator = authenticator
	return client, nil
}

func newHTTPSClient(cert []byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("Can't append Conjur SSL cert")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Transport: tr, Timeout: time.Second * 10}, nil
}
