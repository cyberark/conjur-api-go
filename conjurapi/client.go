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
)

type Authenticator interface {
	RefreshToken() ([]byte, error)
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

	// Sub-client for v2 API operations
	v2 *V2Client
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

func newClientFromStoredCredentials(config Config) (*Client, error) {
	if config.AuthnType == "oidc" {
		return newClientFromStoredOidcCredentials(config)
	}

	if config.AuthnType == "iam" {
		return newClientFromStoredAWSConfig(config)
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

func (c *Client) V2() *V2Client {
	if c.v2 == nil {
		c.v2 = &V2Client{c}
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
		httpClient = &http.Client{
			Transport: newHTTPTransport(),
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
		return nil, fmt.Errorf("Can't append Conjur SSL cert")
	}
	//TODO: Test what happens if this cert is expired
	//TODO: What if server cert is rotated
	tr := newHTTPTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(config.GetHttpTimeout())}, nil
}

func newHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: time.Second * time.Duration(HTTPDailTimeout),
		}).DialContext,
	}
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
