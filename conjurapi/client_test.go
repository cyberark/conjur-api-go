package conjurapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sample_cert = `
-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----
`

func TestNewClientFromKey(t *testing.T) {
	t.Run("Has authenticator of type APIKeyAuthenticator", func(t *testing.T) {
		client, err := NewClientFromKey(
			Config{Account: "account", ApplianceURL: "appliance-url"},
			authn.LoginPair{Login: "login", APIKey: "api-key"},
		)

		require.NoError(t, err)
		assert.IsType(t, &authn.APIKeyAuthenticator{}, client.authenticator)
	})
}

func TestClient_GetConfig(t *testing.T) {
	t.Run("Returns Client Config", func(t *testing.T) {
		expectedConfig := Config{
			Account:           "some-account",
			ApplianceURL:      "some-appliance-url",
			NetRCPath:         "some-netrc-path",
			SSLCert:           "some-ssl-cert",
			SSLCertPath:       "some-ssl-cert-path",
			DisableKeepAlives: true,
		}
		client := Client{
			config: expectedConfig,
		}

		assert.EqualValues(t, client.GetConfig(), expectedConfig)
	})
}

func TestNewClientFromTokenFile(t *testing.T) {
	t.Run("Has authenticator of type TokenFileAuthenticator", func(t *testing.T) {
		client, err := NewClientFromTokenFile(Config{Account: "account", ApplianceURL: "appliance-url"}, "token-file")

		require.NoError(t, err)
		assert.IsType(t, &authn.TokenFileAuthenticator{}, client.authenticator)
	})
	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		client, err := NewClientFromTokenFile(Config{Account: "account", ApplianceURL: "https://appliance-url", SSLCertPath: "fake-path"}, "token-file")

		assert.EqualError(t, err, "open fake-path: no such file or directory")
		assert.Nil(t, client)
	})
}

func TestNewClientFromEnvironment(t *testing.T) {
	t.Run("Calls NewClientFromTokenFile when CONJUR_AUTHN_TOKEN_FILE is set", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		os.Setenv("CONJUR_AUTHN_TOKEN_FILE", "token-file")
		os.Setenv("HOME", t.TempDir())
		client, err := NewClientFromEnvironment(config)
		require.NoError(t, err)
		assert.IsType(t, &authn.TokenFileAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromToken when CONJUR_AUTHN_TOKEN is set", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		os.Setenv("CONJUR_AUTHN_TOKEN", "some-token")
		os.Setenv("HOME", t.TempDir())
		client, err := NewClientFromEnvironment(config)
		require.NoError(t, err)
		assert.IsType(t, &authn.TokenAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromJwt when CONJUR_AUTHN_JWT_SERVICE is set", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		os.Setenv("CONJUR_AUTHN_JWT_SERVICE_ID", "jwt-service")
		os.Setenv("HOME", t.TempDir())
		client, err := NewClientFromEnvironment(config)
		require.NoError(t, err)
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromKey with when LoginPair is retrieved from env variables", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		os.Setenv("CONJUR_AUTHN_LOGIN", "user")
		os.Setenv("CONJUR_AUTHN_API_KEY", "password")
		os.Setenv("HOME", t.TempDir())
		client, err := NewClientFromEnvironment(config)
		require.NoError(t, err)
		assert.IsType(t, &authn.APIKeyAuthenticator{}, client.authenticator)
	})

	t.Run("Returns error when config is invalid", func(t *testing.T) {
		config := Config{Account: ""}
		client, err := NewClientFromEnvironment(config)
		assert.ErrorContains(t, err, "Must specify an Account")
		assert.Nil(t, client)
	})

	t.Run("Returns error when no credentials found", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		config := Config{Account: "account", ApplianceURL: "appliance-url", CredentialStorage: "none"}
		os.Setenv("CONJUR_AUTHN_LOGIN", "")
		os.Setenv("CONJUR_AUTHN_API_KEY", "")
		os.Setenv("HOME", t.TempDir())

		client, err := NewClientFromEnvironment(config)
		assert.EqualError(t, err, "No valid credentials found. Please login again.")
		assert.Nil(t, client)
	})

	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("CONJUR_AUTHN_LOGIN", "user")
		os.Setenv("CONJUR_AUTHN_API_KEY", "password")
		os.Setenv("HOME", t.TempDir())
		client, err := NewClientFromEnvironment(Config{Account: "account", ApplianceURL: "https://appliance-url", SSLCertPath: "fake-path"})

		assert.EqualError(t, err, "open fake-path: no such file or directory")
		assert.Nil(t, client)
	})
}

func TestNewClientFromJwt(t *testing.T) {
	t.Run("Fetches config but fails due to unreachable host", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "https://appliance-url",
			SSLCert:      sample_cert,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTContent:   "jwt-token",
		}

		client, err := NewClientFromJwt(config)
		assert.NoError(t, err)
		require.NotNil(t, client)

		// Verify that the client authenticator is of type TokenAuthenticator
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)

		// Expect it to fail without a mocked JWT server
		token, err := client.authenticator.(*authn.JWTAuthenticator).RefreshToken()
		require.Error(t, err)
		assert.Equal(t, "", string(token))
	})

	t.Run("Fetches config and succeeds", func(t *testing.T) {
		// Listen for JWT authentication requests
		mockConjurServer := mockConjurServerWithJWT()
		defer mockConjurServer.Close()

		config := Config{
			Account:      "myaccount",
			ApplianceURL: mockConjurServer.URL,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTContent:   "jwt-token",
		}

		client, err := NewClientFromJwt(config)
		assert.NoError(t, err)
		assert.NotNil(t, client)

		// Verify that the client authenticator is of type TokenAuthenticator
		require.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)

		// Verify that the JWT authenticator succeeds
		token, err := client.authenticator.(*authn.JWTAuthenticator).RefreshToken()
		require.NoError(t, err)
		assert.Equal(t, "test-access-token", string(token))
	})

	t.Run("Fetches JWT from file", func(t *testing.T) {
		// Listen for JWT authentication requests
		mockConjurServer := mockConjurServerWithJWT()
		defer mockConjurServer.Close()

		tempDir := t.TempDir()
		err := os.WriteFile(tempDir+"/jwt-token", []byte("jwt-token"), 0644)
		require.NoError(t, err)

		config := Config{
			Account:      "myaccount",
			ApplianceURL: mockConjurServer.URL,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTFilePath:  tempDir + "/jwt-token",
		}

		client, err := NewClientFromJwt(config)
		assert.NoError(t, err)
		require.NotNil(t, client)

		// Verify that the client authenticator is of type TokenAuthenticator
		require.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)
		// Verify that the JWT token is read correctly
		client.authenticator.(*authn.JWTAuthenticator).RefreshJWT()
		assert.Equal(t, "jwt-token", client.authenticator.(*authn.JWTAuthenticator).JWT)
	})

	t.Run("Fetches config and fails with incorrect JWT", func(t *testing.T) {
		// Listen for JWT authentication requests
		mockConjurServer := mockConjurServerWithJWT()
		defer mockConjurServer.Close()

		config := Config{
			Account:      "myaccount",
			ApplianceURL: mockConjurServer.URL,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTContent:   "incorrect-jwt-token",
		}

		client, err := NewClientFromJwt(config)
		require.NoError(t, err)

		// Expect it to fail without a mocked JWT server
		token, err := client.authenticator.RefreshToken()
		assert.ErrorContains(t, err, "401 Unauthorized")
		assert.Equal(t, "", string(token))
	})

	t.Run("Appends JWT Host ID to authn URL", func(t *testing.T) {
		// Listen for JWT authentication requests
		mockConjurServer := mockConjurServerWithJWT()
		defer mockConjurServer.Close()

		config := Config{
			Account:      "myaccount",
			ApplianceURL: mockConjurServer.URL,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTContent:   "jwt-token",
			JWTHostID:    "my-host", // This should be added to the authn URL
		}

		client, err := NewClientFromJwt(config)
		assert.NoError(t, err)
		require.NotNil(t, client)

		// Verify that the JWT authenticator succeeds
		token, err := client.authenticator.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, "test-access-token-with-host-id", string(token))
	})

	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "https://appliance-url",
			SSLCertPath:  "fake-path",
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTContent:   "jwt-token",
		}

		client, err := NewClientFromJwt(config)

		assert.EqualError(t, err, "open fake-path: no such file or directory")
		assert.Nil(t, client)
	})
}

func Test_newClientWithAuthenticator(t *testing.T) {
	t.Run("Returns nil and error for invalid config", func(t *testing.T) {
		client, err := newClientWithAuthenticator(Config{}, nil)

		assert.Nil(t, client)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Must specify")
	})

	t.Run("Returns client without error for valid config", func(t *testing.T) {
		client, err := newClientWithAuthenticator(Config{Account: "account", ApplianceURL: "appliance-url"}, nil)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestNewClientFromToken(t *testing.T) {
	t.Run("Has authenticator of type TokenAuthenticator", func(t *testing.T) {
		client, err := NewClientFromToken(Config{Account: "account", ApplianceURL: "appliance-url"}, "token")

		require.NoError(t, err)
		assert.IsType(t, &authn.TokenAuthenticator{}, client.authenticator)
	})
}

func TestNewClientFromOidcCode(t *testing.T) {
	t.Run("Has authenticator of type OidcAuthenticator", func(t *testing.T) {
		config := Config{ServiceID: "test", AuthnType: "oidc", Account: "account", ApplianceURL: "appliance-url"}
		client, err := NewClientFromOidcCode(config, "test-code", "test-nonce", "test-code-verifier")

		require.NoError(t, err)
		assert.IsType(t, &authn.OidcAuthenticator{}, client.authenticator)
	})
}

func Test_newClientFromStoredCredentials(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		Account:           "account",
		ApplianceURL:      "appliance-url",
		CredentialStorage: "file",
		NetRCPath:         filepath.Join(tempDir, ".netrc"),
	}

	t.Run("Returns error when no credentials are stored", func(t *testing.T) {
		client, err := newClientFromStoredCredentials(config)

		assert.Error(t, err)
		assert.Nil(t, client)
	})
	t.Run("Returns a client when stored credentials exist", func(t *testing.T) {
		storageProvider, err := createStorageProvider(config)
		require.NoError(t, err)
		require.NotNil(t, storageProvider)

		err = storageProvider.StoreCredentials("user", "password")
		require.NoError(t, err)
		client, err := newClientFromStoredCredentials(config)
		assert.NoError(t, err, "Unexpected error: %v", err)
		assert.NotNil(t, client, "Expected client, got error: %v", err)
	})

	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		badCertConfig := Config{
			Account:           "account",
			ApplianceURL:      "https://appliance-url",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(tempDir, ".netrc"),
			SSLCertPath:       "fake-path",
		}

		if storageProvider, _ := createStorageProvider(badCertConfig); storageProvider != nil {
			storageProvider.StoreCredentials("user", "password")
		}
		client, err := newClientFromStoredCredentials(badCertConfig)
		assert.EqualError(t, err, "open fake-path: no such file or directory")
		assert.Nil(t, client)
	})

	t.Run("Returns error when .netrc does not match appliance URL", func(t *testing.T) {
		netrcContent := `
	machine another-url.example.com
		login netrc-login
		password netrc-api-key
	`
		err := os.WriteFile(config.NetRCPath, []byte(netrcContent), 0600)
		assert.NoError(t, err)
		storageProvider, err := createStorageProvider(config)
		assert.NoError(t, err)
		assert.NotNil(t, storageProvider)

		client, err := newClientFromStoredCredentials(config)
		assert.Nil(t, client)
		assert.Error(t, err)
		assert.Contains(t, err.Error(),
			".netrc file was read, but credential for machine appliance-url/authn was not found.")
	})

	t.Run("Cloud auth: Returns client from stored host API key credentials", func(t *testing.T) {
		cloudTempDir := t.TempDir()
		cloudConfig := Config{
			Account:           "account",
			ApplianceURL:      "appliance-url",
			AuthnType:         "cloud",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(cloudTempDir, ".netrc"),
		}

		// Store host API key credentials
		storageProvider, err := createStorageProvider(cloudConfig)
		require.NoError(t, err)
		err = storageProvider.StoreCredentials("host/cloud-host", "host-api-key")
		require.NoError(t, err)

		client, err := newClientFromStoredCredentials(cloudConfig)

		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.IsType(t, &authn.APIKeyAuthenticator{}, client.authenticator)
	})

	t.Run("Cloud auth: Falls back to OIDC when no API key credentials found", func(t *testing.T) {
		cloudTempDir := t.TempDir()
		cloudConfig := Config{
			Account:           "account",
			ApplianceURL:      "appliance-url",
			AuthnType:         "cloud",
			ServiceID:         "cloud-service",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(cloudTempDir, ".netrc"),
		}

		// Store OIDC token (indicated by special [oidc] login)
		storageProvider, err := createStorageProvider(cloudConfig)
		require.NoError(t, err)
		err = storageProvider.StoreAuthnToken([]byte(sample_token))
		require.NoError(t, err)

		client, err := newClientFromStoredCredentials(cloudConfig)

		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.IsType(t, &authn.OidcAuthenticator{}, client.authenticator)
	})

	t.Run("Cloud auth: Skips OIDC token and tries actual OIDC login when login is [oidc]", func(t *testing.T) {
		cloudTempDir := t.TempDir()
		cloudConfig := Config{
			Account:           "account",
			ApplianceURL:      "appliance-url",
			AuthnType:         "cloud",
			ServiceID:         "cloud-service",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(cloudTempDir, ".netrc"),
		}

		// Manually store credentials with [oidc] as login (shouldn't be used for host auth)
		netrcContent := `
machine appliance-url/authn-cloud/cloud-service
	login [oidc]
	password some-oidc-token-data
`
		err := os.WriteFile(cloudConfig.NetRCPath, []byte(netrcContent), 0600)
		require.NoError(t, err)

		// Should skip the [oidc] credentials and try OIDC flow
		client, err := newClientFromStoredCredentials(cloudConfig)

		// Will error because no valid OIDC token, but verifies it went to OIDC path
		assert.Error(t, err)
		assert.Nil(t, client)
	})

	t.Run("Cloud auth: Uses authn endpoint for host with ServiceID set to conjur", func(t *testing.T) {
		cloudTempDir := t.TempDir()
		cloudConfig := Config{
			Account:           "account",
			ApplianceURL:      "appliance-url",
			AuthnType:         "cloud",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(cloudTempDir, ".netrc"),
		}

		// Store host credentials
		storageProvider, err := createStorageProvider(cloudConfig)
		require.NoError(t, err)
		err = storageProvider.StoreCredentials("host/cloud-host", "api-key")
		require.NoError(t, err)

		client, err := newClientFromStoredCredentials(cloudConfig)

		assert.NoError(t, err)
		assert.NotNil(t, client)
		// Verify it's using authn, not authn-cloud
		assert.Equal(t, "authn", client.config.AuthnType)
	})

	t.Run("Cloud auth: Returns error when no credentials found", func(t *testing.T) {
		cloudTempDir := t.TempDir()
		cloudConfig := Config{
			Account:           "account",
			ApplianceURL:      "appliance-url",
			AuthnType:         "cloud",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(cloudTempDir, ".netrc"),
		}

		client, err := newClientFromStoredCredentials(cloudConfig)

		assert.Error(t, err)
		assert.Nil(t, client)
	})
}

func Test_newClientFromStoredOidcCredentials(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		ServiceID:         "test",
		AuthnType:         "oidc",
		Account:           "account",
		ApplianceURL:      "appliance-url",
		CredentialStorage: "file",
		NetRCPath:         filepath.Join(tempDir, ".netrc"),
	}
	t.Run("Returns error when no OIDC credentials are stored", func(t *testing.T) {
		client, err := newClientFromStoredOidcCredentials(config)

		assert.Error(t, err)
		assert.Nil(t, client)
	})
	t.Run("Returns a client when OIDC credentials exist", func(t *testing.T) {
		if storageProvider, _ := createStorageProvider(config); storageProvider != nil {
			storageProvider.StoreAuthnToken([]byte(sample_token))
		}
		client, err := newClientFromStoredCredentials(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		badCertConfig := Config{
			ServiceID:         "test",
			AuthnType:         "oidc",
			Account:           "account",
			ApplianceURL:      "appliance-url",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(tempDir, ".netrc"),
			SSLCertPath:       "fake-path",
		}

		if storageProvider, _ := createStorageProvider(badCertConfig); storageProvider != nil {
			storageProvider.StoreCredentials("user", "password")
		}
		client, err := newClientFromStoredCredentials(badCertConfig)

		assert.EqualError(t, err, "open fake-path: no such file or directory")
		assert.Nil(t, client)
	})
}

func TestClient_GetAuthenticator(t *testing.T) {
	t.Run("Get authenticator", func(t *testing.T) {
		authenticator := &authn.APIKeyAuthenticator{}
		client := Client{authenticator: authenticator}

		assert.Equal(t, authenticator, client.GetAuthenticator())
	})
}

func TestClient_SetAuthenticator(t *testing.T) {
	t.Run("Set authenticator", func(t *testing.T) {
		authenticator := &authn.APIKeyAuthenticator{}
		client := Client{}
		client.SetAuthenticator(authenticator)

		assert.Equal(t, authenticator, client.authenticator)
	})
}

func TestClient_GetHttpClient(t *testing.T) {
	t.Run("Get HTTP client", func(t *testing.T) {
		httpClient := &http.Client{}
		client := Client{httpClient: httpClient}

		assert.Equal(t, httpClient, client.GetHttpClient())
	})
}

func TestClient_SetHttpClient(t *testing.T) {
	t.Run("Set HTTP client", func(t *testing.T) {
		httpClient := &http.Client{}
		client := Client{}
		client.SetHttpClient(httpClient)

		assert.Equal(t, httpClient, client.httpClient)
	})
}

func TestClient_createHttpClient(t *testing.T) {
	t.Run("Create HTTP client with HTTPS and valid cert", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "https://appliance-url", SSLCert: sample_cert}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestClient_newHTTPSClient(t *testing.T) {
	t.Run("New HTTPS client error with invalid cert", func(t *testing.T) {
		config := Config{}
		client, err := newHTTPSClient([]byte("invalid cert"), config)

		assert.EqualError(t, err, "Can't append Secrets Manager SSL cert")
		assert.Nil(t, client)
	})
	t.Run("New HTTPS client with valid cert", func(t *testing.T) {
		config := Config{}
		client, err := newHTTPSClient([]byte(sample_cert), config)

		assert.NoError(t, err)
		assert.NotNil(t, client)

		t.Run("Maintains default proxy", func(t *testing.T) {
			transport, ok := client.Transport.(*http.Transport)
			require.True(t, ok, "Transport is not of type *http.Transport")
			require.NotNil(t, transport)
			assert.ObjectsAreEqual(http.ProxyFromEnvironment, transport.Proxy)
		})
	})
}

func TestClient_HttpClientTimeoutValue(t *testing.T) {
	t.Run("Create HTTP client with default timeout value", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url"}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, time.Second*time.Duration(HTTPTimeoutDefaultValue), client.Timeout)
	})
	t.Run("Create HTTP client with negative timeout", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url", HTTPTimeout: -1}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, time.Second*time.Duration(HTTPTimeoutDefaultValue), client.Timeout)
	})
	t.Run("Create HTTP client with specific timeout", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url", HTTPTimeout: 5}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, time.Second*time.Duration(5), client.Timeout)
	})
}

func mockConjurServerWithJWT() *httptest.Server {
	mockConjurServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Listen for requests to the JWT authenticate endpoint
		if strings.HasSuffix(r.URL.Path, "/authn-jwt/jwt-service/myaccount/authenticate") {
			// Check that the request body contains the JWT token
			body, _ := io.ReadAll(r.Body)

			if string(body) == "jwt=jwt-token" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test-access-token"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else if strings.HasSuffix(r.URL.Path, "/authn-jwt/jwt-service/myaccount/my-host/authenticate") {
			// When a host is specified, return a different access token
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-access-token-with-host-id"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return mockConjurServer
}

func TestClient_DisableKeepAlive(t *testing.T) {
	t.Run("Returns default disableKeepAlives value", func(t *testing.T) {
		expectedConfig := Config{
			Account: "some-account",
		}
		client := Client{
			config: expectedConfig,
		}

		assert.EqualValues(t, client.GetConfig().DisableKeepAlives, false)
	})

	t.Run("Check default option disableKeepAlive must be false", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("CONJUR_DISABLE_KEEP_ALIVES", "error")
		os.Setenv("HOME", t.TempDir())
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		client := Client{
			config: config,
		}
		assert.NotNil(t, client)
		assert.Equal(t, client.GetConfig().DisableKeepAlives, false)
	})

	t.Run("Returns ok when CONJUR_DISABLE_KEEP_ALIVES is set to true", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")
		os.Setenv("CONJUR_AUTHN_LOGIN", "user")
		os.Setenv("CONJUR_AUTHN_API_KEY", "password")
		os.Setenv("CONJUR_DISABLE_KEEP_ALIVES", "true")
		os.Setenv("HOME", t.TempDir())
		config, err := LoadConfig()
		assert.NoError(t, err)
		client, err := NewClient(config)
		assert.NotNil(t, client)
		assert.NoError(t, err)
		assert.Equal(t, client.GetConfig().DisableKeepAlives, true)
	})

	t.Run("Returns ok when disableKeepAlives is set in config", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("CONJUR_AUTHN_LOGIN", "user")
		os.Setenv("CONJUR_AUTHN_API_KEY", "password")
		os.Setenv("HOME", t.TempDir())
		config := Config{Account: "account", ApplianceURL: "appliance-url", DisableKeepAlives: true}
		client := Client{
			config: config,
		}
		assert.NotNil(t, client)
		assert.Equal(t, client.GetConfig().DisableKeepAlives, true)
	})
}

func TestNewClientFromCloudHost(t *testing.T) {
	t.Run("Creates authenticated client successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("auth-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL:      server.URL,
			Account:           "conjur",
			AuthnType:         "cloud",
			CredentialStorage: "none",
		}

		client, err := NewClientFromCloudHost(config, "host/cloud-host", "host-api-key")

		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "cloud", client.config.AuthnType)
		assert.NotNil(t, client.authenticator)
	})

	t.Run("Returns error when authentication fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL:      server.URL,
			Account:           "conjur",
			AuthnType:         "cloud",
			CredentialStorage: "none",
		}

		client, err := NewClientFromCloudHost(config, "host/cloud-host", "wrong-api-key")

		assert.Error(t, err)
		assert.Nil(t, client)
	})

	t.Run("Returns error with invalid config", func(t *testing.T) {
		config := Config{
			Account:   "conjur",
			AuthnType: "cloud",
		}

		client, err := NewClientFromCloudHost(config, "host/cloud-host", "api-key")

		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to create auth client")
	})

	t.Run("Stores credentials with file storage", func(t *testing.T) {
		tempDir := t.TempDir()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("auth-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL:      server.URL,
			Account:           "conjur",
			AuthnType:         "cloud",
			CredentialStorage: "file",
			NetRCPath:         filepath.Join(tempDir, ".netrc"),
		}

		client, err := NewClientFromCloudHost(config, "host/test-host", "test-api-key")

		assert.NoError(t, err)
		assert.NotNil(t, client)

		storageProvider, err := createStorageProvider(config)
		require.NoError(t, err)
		login, password, err := storageProvider.ReadCredentials()
		assert.NoError(t, err)
		assert.Equal(t, "host/test-host", login)
		assert.Equal(t, "test-api-key", password)
	})

	t.Run("Handles storage errors gracefully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL:      server.URL,
			Account:           "conjur",
			AuthnType:         "cloud",
			CredentialStorage: "invalid-storage",
		}

		client, err := NewClientFromCloudHost(config, "host/cloud-host", "api-key")

		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to create")
	})
}
