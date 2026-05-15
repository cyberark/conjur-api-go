package conjurapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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

func NewClientFromKey(config Config, loginPair authn.LoginPair, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.APIKeyAuthenticator{
		LoginPair: loginPair,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	authenticator.Authenticate = client.Authenticate
	return client, err
}

// NewClientFromCloudHost creates an authenticated client for a Secrets Manager SaaS host.
// Uses the Authenticate endpoint to validate the API key. Returns error if authentication fails.
// Config.AuthnType should be "cloud" for proper credential storage.
func NewClientFromCloudHost(config Config, login string, password string, telemetry ...Telemetry) (*Client, error) {
	storageProvider, err := createStorageProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage provider: %w", err)
	}

	authClient, err := newCloudAuthClient(config, storageProvider, telemetry...)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth client: %w", err)
	}

	apiKey, err := authClient.CloudHostLogin(login, password)
	if err != nil {
		return nil, err
	}

	return NewClientFromKey(config, authn.LoginPair{Login: login, APIKey: string(apiKey)}, telemetry...)
}

// newCloudAuthClient creates a temporary client for cloud host authentication using standard authn endpoints.
// Cloud hosts must use AuthnType="authn" (routes to /authn/{Account}/{login}) instead of AuthnType="cloud"
// (routes to /authn-oidc/... for users). Storage uses original cloud config to ensure correct machine name.
func newCloudAuthClient(config Config, storage CredentialStorageProvider, telemetry ...Telemetry) (*Client, error) {
	authConfig := config
	authConfig.AuthnType = AuthnTypeStandard

	client, err := NewClient(authConfig, telemetry...)
	if err != nil {
		return nil, err
	}

	client.storage = storage
	return client, nil
}

func NewClientFromOidcCode(config Config, code, nonce, code_verifier string, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.OidcAuthenticator{
		Code:         code,
		Nonce:        nonce,
		CodeVerifier: code_verifier,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.OidcAuthenticate
	}
	return client, err
}

func NewClientFromAWSCredentials(config Config, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.IAMAuthenticator{}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.IAMAuthenticate
	}
	return client, err
}

func NewClientFromGCPCredentials(config Config, identityUrl string, telemetry ...Telemetry) (*Client, error) {
	if identityUrl == "" {
		identityUrl = authn.GcpIdentityURL
	}
	authenticator := &authn.GCPAuthenticator{
		Account:        config.Account,
		HostID:         config.JWTHostID,
		JWT:            config.JWTContent,
		GCPIdentityUrl: identityUrl,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.GCPAuthenticate
	}
	return client, err
}

func NewClientFromAzureCredentials(config Config, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.AzureAuthenticator{
		JWT:      config.JWTContent,
		ClientID: config.AzureClientID,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.AzureAuthenticate
	}
	return client, err
}

func NewClientFromOidcToken(config Config, token string, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.OidcTokenAuthenticator{
		Token: token,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
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

func NewClientFromToken(config Config, token string, telemetry ...Telemetry) (*Client, error) {
	return newClientWithAuthenticator(config, &authn.TokenAuthenticator{Token: token}, telemetry...)
}

func NewClientFromTokenFile(config Config, tokenFile string, telemetry ...Telemetry) (*Client, error) {
	return newClientWithAuthenticator(
		config,
		&authn.TokenFileAuthenticator{TokenFile: tokenFile, MaxWaitTime: -1},
		telemetry...,
	)
}

func LoginPairFromEnv() (*authn.LoginPair, error) {
	return &authn.LoginPair{
		Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
		APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
	}, nil
}

// NewClientFromEnvironment constructs a new Client instance from a given Config
// instance, but prioritizes environment variables for authenticator
// configuration. Authenticator configuration is prioritized as follows:
//  1. CONJUR_AUTHN_TOKEN_FILE                           -> TokenFileAuthenticator
//  2. CONJUR_AUTHN_TOKEN                                -> TokenAuthenticator
//  3. config.AuthnType "cert"                           -> CertAuthenticator
//     (which heavily implies CONJUR_AUTHN_CERT_SERVICE_ID, especially is the
//     Config instance is created with the LoadConfig function, which
//     prioritizes CONJUR_AUTHN_CERT_SERVICE_ID over CONJUR_AUTHN_JWT_SERVICE_ID)
//  4. CONJUR_AUTHN_JWT_SERVICE_ID or config.JWTFilePath -> JWTAuthenticator
//  5. CONJUR_AUTHN_LOGIN and CONJUR_AUTHN_API_KEY       -> APIKeyAuthenticator
//  6. Other config.AuthnType values
//
// TODO: Create a version of this function for creating an authenticator from environment
func NewClientFromEnvironment(config Config, telemetry ...Telemetry) (*Client, error) {
	err := config.Validate()

	if err != nil {
		return nil, err
	}

	maybeLogOverwrite := func() {
		if config.AuthnType != "" {
			logging.ApiLog.Debugf("Config instance with AuthnType '%s' detected, it is being ignored", config.AuthnType)
		}
	}

	authnTokenFile := os.Getenv("CONJUR_AUTHN_TOKEN_FILE")
	if authnTokenFile != "" {
		logging.ApiLog.Debug("CONJUR_AUTHN_TOKEN_FILE environment variable detected, initializing client with token file authenticator")
		maybeLogOverwrite()
		return NewClientFromTokenFile(config, authnTokenFile, telemetry...)
	}

	authnToken := os.Getenv("CONJUR_AUTHN_TOKEN")
	if authnToken != "" {
		logging.ApiLog.Debug("CONJUR_AUTHN_TOKEN environment variable detected, initializing client with token authenticator")
		maybeLogOverwrite()
		return NewClientFromToken(config, authnToken, telemetry...)
	}

	if config.AuthnType == "cert" {
		logging.ApiLog.Debug("Config instance with authn type 'cert' detected, initializing client with certificate authenticator")
		if os.Getenv("CONJUR_AUTHN_API_KEY") != "" {
			logging.ApiLog.Warn("CONJUR_AUTHN_API_KEY environment variable detected, it is being ignored")
		}
		return newClientFromCertConfig(config, telemetry...)
	}

	if config.JWTFilePath != "" || os.Getenv("CONJUR_AUTHN_JWT_SERVICE_ID") != "" {
		logging.ApiLog.Debug("CONJUR_AUTHN_JWT_SERVICE_ID environment variable detected, initializing client with JWT authenticator")
		maybeLogOverwrite()
		return NewClientFromJwt(config, telemetry...)
	}

	loginPair, err := LoginPairFromEnv()
	if err == nil && loginPair.Login != "" && loginPair.APIKey != "" {
		logging.ApiLog.Debug("CONJUR_AUTHN_LOGIN and CONJUR_AUTHN_API_KEY environment variables detected, initializing client with API key authenticator")
		maybeLogOverwrite()
		return NewClientFromKey(config, *loginPair, telemetry...)
	}

	logging.ApiLog.Debug("No environment variables detected for authentication, falling back to stored credentials")
	return newClientFromStoredCredentials(config, telemetry...)
}

// NewClientFromCertificate creates a Client that authenticates using the authn-cert
// (mutual TLS) authenticator. The mTLS transport is configured automatically from
// config.ClientCertFile/ClientCertKeyFile or config.ClientCert/ClientCertKey.
func NewClientFromCertificate(config Config, telemetry ...Telemetry) (*Client, error) {
	// Eagerly verify the certificate can be loaded to surface config errors at
	// construction time rather than at the first TLS handshake.
	if _, err := config.ReadClientCert(); err != nil {
		return nil, fmt.Errorf("cannot load client certificate: %w", err)
	}
	authenticator := &authn.CertAuthenticator{
		HostID: config.CertHostID,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.CertAuthenticate
	}
	return client, err
}

func NewClientFromJwt(config Config, telemetry ...Telemetry) (*Client, error) {
	authenticator := &authn.JWTAuthenticator{
		JWT:         config.JWTContent,
		JWTFilePath: config.JWTFilePath,
		HostID:      config.JWTHostID,
	}
	client, err := newClientWithAuthenticator(config, authenticator, telemetry...)
	if err == nil {
		authenticator.Authenticate = client.JWTAuthenticate
	}
	return client, err
}

// newClientFromStoredCredentials creates a client using credentials from storage.
// Routes to appropriate credential retrieval based on config.AuthnType (oidc, cloud, iam, azure, gcp).
// For cloud type, tries host API key credentials first, then falls back to OIDC for users.
// Returns error if no valid credentials found in storage.
//
// Auth types that do not use stored credentials (e.g. cert, jwt) must be handled by
// the caller before reaching this function; passing them here returns an explicit error.
func newClientFromStoredCredentials(config Config, telemetry ...Telemetry) (*Client, error) {
	switch config.AuthnType {
	case "oidc":
		return newClientFromStoredOidcCredentials(config, telemetry...)

	case AuthnTypeCloud:
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

				logging.ApiLog.Debug("Host credentials found in storage, initializing client with API key authenticator")
				return NewClientFromKey(hostConfig, authn.LoginPair{Login: login, APIKey: password}, telemetry...)
			}
		}
		logging.ApiLog.Debug("No host credentials found in storage, attempting to authenticate using OIDC credentials")
		return newClientFromStoredOidcCredentials(config, telemetry...)

	case "iam":
		logging.ApiLog.Debug("Config instance with authn type 'iam' detected, initializing client with IAM authenticator")
		return newClientFromStoredAWSConfig(config, telemetry...)

	case "azure":
		logging.ApiLog.Debug("Config instance with authn type 'azure' detected, initializing client with Azure authenticator")
		return newClientFromStoredAzureConfig(config, telemetry...)

	case "gcp":
		logging.ApiLog.Debug("Config instance with authn type 'gcp' detected, initializing client with GCP authenticator")
		return newClientFromStoredGCPConfig(config, telemetry...)

	case "", AuthnTypeStandard:
		// Fall through to generic storage lookup below.

	default:
		return nil, fmt.Errorf("auth type %q does not use stored credentials", config.AuthnType)
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
			logging.ApiLog.Debug("Credentials found in storage, initializing client with API key authenticator")
			return NewClientFromKey(config, authn.LoginPair{Login: login, APIKey: password}, telemetry...)
		}
	}

	return nil, fmt.Errorf("No valid credentials found. Please login again.")
}

func newClientFromStoredOidcCredentials(config Config, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClientFromOidcCode(config, "", "", "", telemetry...)
	if err != nil {
		return nil, err
	}
	token := client.readCachedAccessToken()
	if token != nil && !token.ShouldRefresh() {
		return client, nil
	}
	return nil, fmt.Errorf("No valid OIDC token found. Please login again. " +
		"If this error recurs shortly after logging in, verify your system clock is synchronized.")
}

// TODO: Refactor to remove code duplication between authn-iam, authn-gcp, and authn-azure (and possibly authn-oidc and authn-jwt)
func newClientFromStoredAWSConfig(config Config, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClientFromAWSCredentials(config, telemetry...)
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

func newClientFromStoredAzureConfig(config Config, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClientFromAzureCredentials(config, telemetry...)
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

func newClientFromStoredGCPConfig(config Config, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClientFromGCPCredentials(config, authn.GcpIdentityURL, telemetry...)
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

func newClientFromCertConfig(config Config, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClientFromCertificate(config, telemetry...)
	if err != nil {
		return nil, err
	}

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

// NewClient creates a new Client with the given Config.
// An optional Telemetry struct can be passed to override integration metadata.
// If telemetry is not provided, defaults from constants are used.
//
// Usage:
//
//	client, err := NewClient(config)  // Uses default telemetry
//	client, err := NewClient(config, telemetry)  // Uses custom telemetry
func NewClient(config Config, telemetry ...Telemetry) (*Client, error) {
	var err error

	err = config.Validate()

	if err != nil {
		return nil, err
	}

	t := resolveTelemetry(telemetry...)
	config.IntegrationName = t.IntegrationName
	config.IntegrationType = t.IntegrationType
	config.IntegrationVersion = t.IntegrationVersion
	config.VendorName = t.VendorName
	config.VendorVersion = t.VendorVersion
	config.SetFinalTelemetryHeader()

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

	if config.AuthnType == "cert" {
		if !strings.HasPrefix(strings.ToLower(config.BaseURL()), "https://") {
			return nil, fmt.Errorf("certificate authentication requires an HTTPS connection")
		}
		var caCert []byte
		if config.IsHttps() {
			var err error
			caCert, err = config.ReadSSLCert()
			if err != nil {
				return nil, err
			}
		}
		return newMTLSClient(caCert, config)
	}

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

func newClientWithAuthenticator(config Config, authenticator Authenticator, telemetry ...Telemetry) (*Client, error) {
	client, err := NewClient(config, telemetry...)
	if err != nil {
		return nil, err
	}

	client.authenticator = authenticator
	return client, nil
}

func resolveTelemetry(telemetry ...Telemetry) Telemetry {
	if len(telemetry) > 0 {
		return telemetry[0]
	}
	return NewTelemetry("", "", "", "", "")
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
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(config.GetHttpTimeout())}, nil
}

// newMTLSClient builds an HTTP client for authn-cert mutual TLS.
// When file paths are configured the certificate is re-read on every TLS handshake, enabling
// transparent rotation for long-running workloads. When inline PEM is provided the certificate
// is parsed once at construction time — inline content never changes so re-parsing is unnecessary.
// If caCert is non-empty it is added to a custom RootCAs pool; otherwise the system trust store is used.
func newMTLSClient(caCert []byte, config Config) (*http.Client, error) {
	tr := newHTTPTransport(config)

	var getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	if config.ClientCert != "" && config.ClientCertKey != "" {
		// Inline PEM: parse once, return from closure on every handshake.
		cert, err := config.ReadClientCert()
		if err != nil {
			return nil, err
		}
		getCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	} else {
		// File paths: re-read on every handshake to support transparent rotation.
		getCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := config.ReadClientCert()
			if err != nil {
				return nil, err
			}
			return &cert, nil
		}
	}

	tlsCfg := &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: getCert,
	}
	if len(caCert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("Can't append Secrets Manager SSL cert")
		}
		tlsCfg.RootCAs = pool
	}
	tr.TLSClientConfig = tlsCfg
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
