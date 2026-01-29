package conjurapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/cyberark/conjur-api-go/conjurapi/storage"
)

// Authentication type constants
const (
	// AuthnTypeCloud represents cloud-based OIDC authentication for users
	AuthnTypeCloud = "cloud"
	// AuthnTypeStandard represents standard username/password or API key authentication
	AuthnTypeStandard = "authn"
)

// Authenticator defines the interface that all authenticators must implement.
type Authenticator interface {
	// RefreshToken obtains a new Conjur access token.
	RefreshToken() ([]byte, error)
	// NeedsTokenRefresh indicates whether the current token needs to be refreshed.
	NeedsTokenRefresh() bool
}

type CredentialStorageProvider interface {
	StoreCredentials(login string, password string) error
	ReadCredentials() (login string, password string, err error)
	ReadAuthnToken() ([]byte, error)
	StoreAuthnToken(token []byte) error
	PurgeCredentials() error
}

type Client struct {
	config        Config
	authToken     *authn.AuthnToken
	httpClient    *http.Client
	authenticator Authenticator
	storage       CredentialStorageProvider
	conjurVersion string

	// Sub-client for v2 API operations
	v2 *ClientV2
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

// NewClientFromCloudHost creates an authenticated client for a Secrets Manager SaaS host.
// Uses the Authenticate endpoint to validate the API key. Returns error if authentication fails.
// Config.AuthnType should be "cloud" for proper credential storage.
func NewClientFromCloudHost(config Config, login string, password string) (*Client, error) {
	storageProvider, err := createStorageProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage provider: %w", err)
	}

	authClient, err := newCloudAuthClient(config, storageProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %w", err)
	}

	apiKey, err := authClient.CloudHostLogin(login, password)
	if err != nil {
		return nil, err
	}

	return NewClientFromKey(config, authn.LoginPair{Login: login, APIKey: string(apiKey)})
}

// newCloudAuthClient creates a temporary client for cloud host authentication using standard authn endpoints.
// Cloud hosts must use AuthnType="authn" (routes to /authn/{Account}/{login}) instead of AuthnType="cloud"
// (routes to /authn-oidc/... for users). Storage uses original cloud config to ensure correct machine name.
func newCloudAuthClient(config Config, storage CredentialStorageProvider) (*Client, error) {
	authConfig := config
	authConfig.AuthnType = AuthnTypeStandard

	client, err := NewClient(authConfig)
	if err != nil {
		return nil, err
	}

	client.storage = storage
	return client, nil
}

func NewClientFromOidcCode(config Config, code, nonce, code_verifier string) (*Client, error) {
	authenticator := &authn.OidcAuthenticator{
		Code:         code,
		Nonce:        nonce,
		CodeVerifier: code_verifier,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.OidcAuthenticate
	}
	return client, err
}

func NewClientFromAWSCredentials(config Config) (*Client, error) {
	authenticator := &authn.IAMAuthenticator{}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.IAMAuthenticate
	}
	return client, err
}

func NewClientFromGCPCredentials(config Config, identityUrl string) (*Client, error) {
	if identityUrl == "" {
		identityUrl = authn.GcpIdentityURL
	}
	authenticator := &authn.GCPAuthenticator{
		Account:        config.Account,
		HostID:         config.JWTHostID,
		JWT:            config.JWTContent,
		GCPIdentityUrl: identityUrl,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.GCPAuthenticate
	}
	return client, err
}

func NewClientFromAzureCredentials(config Config) (*Client, error) {
	authenticator := &authn.AzureAuthenticator{
		JWT:      config.JWTContent,
		ClientID: config.AzureClientID,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.AzureAuthenticate
	}
	return client, err
}

func NewClientFromOidcToken(config Config, token string) (*Client, error) {
	authenticator := &authn.OidcTokenAuthenticator{
		Token: token,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.OidcTokenAuthenticate
	}
	return client, err
}

// ReadResponseBody fully reads a response and closes it.
func ReadResponseBody(response io.ReadCloser) ([]byte, error) {
	defer response.Close()
	return io.ReadAll(response)
}

func NewClientFromToken(config Config, token string) (*Client, error) {
	return newClientWithAuthenticator(
		config,
		&authn.TokenAuthenticator{Token: token},
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

// TODO: Create a version of this function for creating an authenticator from environment
func NewClientFromEnvironment(config Config) (*Client, error) {
	err := config.Validate()

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

	if config.JWTFilePath != "" || os.Getenv("CONJUR_AUTHN_JWT_SERVICE_ID") != "" {
		return NewClientFromJwt(config)
	}

	loginPair, err := LoginPairFromEnv()
	if err == nil && loginPair.Login != "" && loginPair.APIKey != "" {
		return NewClientFromKey(config, *loginPair)
	}

	return newClientFromStoredCredentials(config)
}

func NewClientFromJwt(config Config) (*Client, error) {
	authenticator := &authn.JWTAuthenticator{
		JWT:         config.JWTContent,
		JWTFilePath: config.JWTFilePath,
		HostID:      config.JWTHostID,
	}
	client, err := newClientWithAuthenticator(
		config,
		authenticator,
	)
	if err == nil {
		authenticator.Authenticate = client.JWTAuthenticate
	}
	return client, err
}

// newClientFromStoredCredentials creates a client using credentials from storage.
// Routes to appropriate credential retrieval based on config.AuthnType (oidc, cloud, iam, azure, gcp).
// For cloud type, tries host API key credentials first, then falls back to OIDC for users.
// Returns error if no valid credentials found in storage.
func newClientFromStoredCredentials(config Config) (*Client, error) {
	if config.AuthnType == "oidc" {
		return newClientFromStoredOidcCredentials(config)
	}

	if config.AuthnType == AuthnTypeCloud {
		storageProvider, err := createStorageProvider(config)
		if err != nil {
			return nil, err
		}
		if storageProvider != nil {
			login, password, err := storageProvider.ReadCredentials()
			if err != nil {
				logging.ApiLog.Debugf("Failed to read credentials from storage: %v", err)
			} else if login != "" && password != "" && login != storage.OidcStorageMarker {
				hostConfig := config
				hostConfig.AuthnType = AuthnTypeStandard
				return NewClientFromKey(hostConfig, authn.LoginPair{Login: login, APIKey: password})
			}
		}
		return newClientFromStoredOidcCredentials(config)
	}

	if config.AuthnType == "iam" {
		return newClientFromStoredAWSConfig(config)
	}

	if config.AuthnType == "azure" {
		return newClientFromStoredAzureConfig(config)
	}

	if config.AuthnType == "gcp" {
		return newClientFromStoredGCPConfig(config)
	}

	// Attempt to load credentials from whatever storage provider is configured
	storageProvider, err := createStorageProvider(config)
	if err != nil {
		return nil, err
	}
	if storageProvider != nil {
		login, password, err := storageProvider.ReadCredentials()
		if err != nil {
			return nil, err
		}
		if login != "" && password != "" {
			return NewClientFromKey(config, authn.LoginPair{Login: login, APIKey: password})
		}
	}

	return nil, fmt.Errorf("No valid credentials found. Please login again.")
}

func newClientFromStoredOidcCredentials(config Config) (*Client, error) {
	client, err := NewClientFromOidcCode(config, "", "", "")
	if err != nil {
		return nil, err
	}
	token := client.readCachedAccessToken()
	if token != nil && !token.ShouldRefresh() {
		return client, nil
	}
	return nil, fmt.Errorf("No valid OIDC token found. Please login again.")
}

// TODO: Refactor to remove code duplication between authn-iam, authn-gcp, and authn-azure (and possibly authn-oidc and authn-jwt)
func newClientFromStoredAWSConfig(config Config) (*Client, error) {
	client, err := NewClientFromAWSCredentials(config)
	if err != nil {
		return nil, err
	}

	// RefreshToken() will first check for a cached token
	// If not found it will go through the authenticator
	err = client.RefreshToken()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func newClientFromStoredAzureConfig(config Config) (*Client, error) {
	client, err := NewClientFromAzureCredentials(config)
	if err != nil {
		return nil, err
	}

	// RefreshToken() will first check for a cached token
	// If not found it will go through the authenticator
	err = client.RefreshToken()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func newClientFromStoredGCPConfig(config Config) (*Client, error) {
	client, err := NewClientFromGCPCredentials(config, authn.GcpIdentityURL)
	if err != nil {
		return nil, err
	}

	// RefreshToken() will first check for a cached token
	// If not found it will go through the authenticator
	err = client.RefreshToken()
	if err != nil {
		return nil, err
	}

	return client, nil
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

func NewClient(config Config) (*Client, error) {
	var err error

	err = config.Validate()

	if err != nil {
		return nil, err
	}

	httpClient, err := createHttpClient(config)
	if err != nil {
		return nil, err
	}

	storageProvider, err := createStorageProvider(config)
	if err != nil {
		return nil, err
	}

	c := &Client{
		config:     config,
		httpClient: httpClient,
		storage:    storageProvider,
	}

	return c, nil
}

func (c *Client) V2() *ClientV2 {
	if c.v2 == nil {
		c.v2 = &ClientV2{Client: c}
	}
	return c.v2
}

func createHttpClient(config Config) (*http.Client, error) {
	var httpClient *http.Client

	if config.IsHttps() {
		cert, err := config.ReadSSLCert()
		if err != nil {
			return nil, err
		}
		httpClient, err = newHTTPSClient(cert, config)
		if err != nil {
			return nil, err
		}
	} else {
		var transport = newHTTPTransport(config)
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   time.Second * time.Duration(config.GetHttpTimeout()),
		}
	}
	return httpClient, nil
}

func newClientWithAuthenticator(config Config, authenticator Authenticator) (*Client, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}

	client.authenticator = authenticator
	return client, nil
}

func newHTTPSClient(cert []byte, config Config) (*http.Client, error) {
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("Can't append Secrets Manager SSL cert")
	}
	//TODO: Test what happens if this cert is expired
	//TODO: What if server cert is rotated
	tr := newHTTPTransport(config)
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(config.GetHttpTimeout())}, nil
}

func newHTTPTransport(cfg Config) *http.Transport {
	// Clone the default transport to preserve its settings (e.g., Proxy)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{
		Timeout: time.Second * time.Duration(HTTPDialTimeout),
	}).DialContext
	if cfg.ProxyURL() != nil {
		tr.Proxy = http.ProxyURL(cfg.ProxyURL())
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}
	tr.DisableKeepAlives = cfg.DisableKeepAlives
	return tr
}

// GetTelemetryHeader returns the base64-encoded telemetry header by calling the
// SetFinalTelemetryHeader method from the Config object associated with the Client.
//
// This method delegates the responsibility of constructing and caching the telemetry
// header to the Config's SetFinalTelemetryHeader method and simply returns the result.
//
// Returns:
//   - string: The base64-encoded telemetry header.
func (c *Client) GetTelemetryHeader() string {
	return c.config.SetFinalTelemetryHeader()
}

// Cleanup function close unused connections
func (c *Client) Cleanup() {
	c.httpClient.CloseIdleConnections()
}
