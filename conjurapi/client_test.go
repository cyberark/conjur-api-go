package conjurapi

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	t.Run("Creates mTLS client for cert AuthnType without CA cert", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "account",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Creates mTLS client for cert AuthnType with custom CA cert", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "account",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			SSLCert:       sample_cert,
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Returns error for cert AuthnType with invalid CA cert", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "account",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			SSLCert:       "not-a-valid-cert",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}
		client, err := createHttpClient(config)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Can't append Secrets Manager SSL cert")
		assert.Nil(t, client)
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

func TestHttpClient_RespectsNoProxyEnv(t *testing.T) {
	// Set up a test server to act as the target
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.WriteHeader(200)
	}))
	defer target.Close()

	// Set up a dummy proxy server
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Proxy should not be used for NO_PROXY hosts")
	}))
	defer proxy.Close()

	// Set environment variables
	os.Setenv("HTTP_PROXY", proxy.URL)
	// Extract hostname from target URL for NO_PROXY
	targetURL, _ := url.Parse(target.URL)
	os.Setenv("NO_PROXY", targetURL.Hostname())
	defer os.Unsetenv("HTTP_PROXY")
	defer os.Unsetenv("NO_PROXY")

	// Create config with the test server's URL as ApplianceURL
	cfg := Config{
		ApplianceURL: target.URL,
		Account:      "test",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make a request to the target server (should not use proxy)
	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !targetCalled {
		t.Errorf("Target server was not called")
	}
}

// mockConjurServerWithCert creates a plain-HTTP test server that handles authn-cert
// authenticate requests for service "test-cert-service" and account "myaccount".
// On success it returns sample_token (a valid Conjur access token) so that
// newClientFromCertConfig can call client.RefreshToken() without error.
// It responds 401 when the URL path contains "unauthorized-host".
func mockConjurServerWithCert() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basePath := "/authn-cert/test-cert-service/myaccount"
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, basePath) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Unauthorized host → 401
		if strings.Contains(r.URL.Path, "unauthorized-host") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// All valid authn-cert requests return a well-formed Conjur token so that
		// callers that invoke client.RefreshToken() can parse the response.
		if strings.HasSuffix(r.URL.Path, "/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(sample_token))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// mockConjurTLSServerWithCert creates an HTTPS test server with the same authn-cert
// handler as mockConjurServerWithCert. It returns the server and the PEM-encoded
// server certificate so callers can trust it via config.SSLCert.
func mockConjurTLSServerWithCert() (*httptest.Server, string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		basePath := "/authn-cert/test-cert-service/myaccount"
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, basePath) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.URL.Path, "unauthorized-host") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(sample_token))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewTLSServer(handler)
	certDER := server.TLS.Certificates[0].Certificate[0]
	serverCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return server, serverCertPEM
}

func TestNewClientFromCertificate(t *testing.T) {
	t.Run("Has authenticator of type CertAuthenticator", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "myaccount",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			ServiceID:     "test-cert-service",
			CertHostID:    "vm-workloads/vm-01",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}

		client, err := NewClientFromCertificate(config)

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.IsType(t, &authn.CertAuthenticator{}, client.authenticator)
	})

	t.Run("CertHostID is stored on authenticator", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "myaccount",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			ServiceID:     "test-cert-service",
			CertHostID:    "vm-workloads/vm-01",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}

		client, err := NewClientFromCertificate(config)

		require.NoError(t, err)
		certAuth := client.authenticator.(*authn.CertAuthenticator)
		assert.Equal(t, "vm-workloads/vm-01", certAuth.HostID)
	})

	t.Run("Empty CertHostID stored on authenticator (SPIFFE mode)", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "myaccount",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			ServiceID:     "test-cert-service",
			CertHostID:    "",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}

		client, err := NewClientFromCertificate(config)

		require.NoError(t, err)
		certAuth := client.authenticator.(*authn.CertAuthenticator)
		assert.Equal(t, "", certAuth.HostID)
	})

	t.Run("Returns error when ClientCertFile does not exist", func(t *testing.T) {
		config := Config{
			Account:           "myaccount",
			ApplianceURL:      "https://conjur.example.com",
			AuthnType:         "cert",
			ServiceID:         "test-cert-service",
			CertHostID:        "vm-01",
			ClientCertFile:    "/nonexistent/cert.pem",
			ClientCertKeyFile: "/nonexistent/key.pem",
		}

		// Eager cert loading in NewClientFromCertificate returns a clear error.
		client, err := NewClientFromCertificate(config)
		require.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "cannot load client certificate")
	})
}

func TestClient_CertAuthenticate(t *testing.T) {
	t.Run("Returns error for Conjur Cloud URL (SaaS guard)", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		client := &Client{
			config: Config{
				Account:       "conjur",
				ApplianceURL:  "https://myorg.secretsmgr.cyberark.cloud",
				AuthnType:     "cert",
				ServiceID:     "acme-vm",
				ClientCert:    certPEM,
				ClientCertKey: keyPEM,
			},
			httpClient: &http.Client{},
		}

		token, err := client.CertAuthenticate("vm-workloads/vm-01")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Certificate authentication is not supported in Secrets Manager SaaS")
		assert.Nil(t, token)
	})

	t.Run("Returns error when server returns 401", func(t *testing.T) {
		server := mockConjurServerWithCert()
		defer server.Close()

		certPEM, keyPEM := generateTestCertPEM(t)
		client := &Client{
			config: Config{
				Account:       "myaccount",
				ApplianceURL:  server.URL,
				AuthnType:     "cert",
				ServiceID:     "test-cert-service",
				ClientCert:    certPEM,
				ClientCertKey: keyPEM,
			},
			httpClient: &http.Client{},
		}

		token, err := client.CertAuthenticate("unauthorized-host")

		require.Error(t, err)
		assert.Nil(t, token)
	})
}

func TestNewMTLSClient(t *testing.T) {
	t.Run("GetClientCertificate callback returns cert for valid inline PEM", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}

		client, err := newMTLSClient(nil, config)
		require.NoError(t, err)

		// Invoke the callback directly — no TLS server needed.
		transport := client.Transport.(*http.Transport)
		tlsCert, err := transport.TLSClientConfig.GetClientCertificate(nil)

		require.NoError(t, err)
		require.NotNil(t, tlsCert)
		assert.NotEmpty(t, tlsCert.Certificate)
	})

	t.Run("GetClientCertificate callback returns error when cert file is missing", func(t *testing.T) {
		config := Config{
			ClientCertFile:    "/nonexistent/cert.pem",
			ClientCertKeyFile: "/nonexistent/key.pem",
		}

		client, err := newMTLSClient(nil, config)
		require.NoError(t, err) // client creation itself is lazy

		transport := client.Transport.(*http.Transport)
		tlsCert, err := transport.TLSClientConfig.GetClientCertificate(nil)

		require.Error(t, err)
		assert.Nil(t, tlsCert)
		assert.Contains(t, err.Error(), "failed to read client certificate file")
	})

	t.Run("Returns error immediately for invalid inline PEM", func(t *testing.T) {
		config := Config{
			ClientCert:    "not-a-valid-pem",
			ClientCertKey: "not-a-valid-key",
		}

		_, err := newMTLSClient(nil, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse client certificate and key")
	})

	t.Run("MinVersion is TLS 1.2", func(t *testing.T) {
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{ClientCert: certPEM, ClientCertKey: keyPEM}

		client, err := newMTLSClient(nil, config)
		require.NoError(t, err)

		transport := client.Transport.(*http.Transport)
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	})
}

func TestNewClientFromCertConfig(t *testing.T) {
	t.Run("Returns error when NewClientFromCertificate fails (invalid CA cert)", func(t *testing.T) {
		// Trigger the NewClientFromCertificate error path by supplying an
		// invalid SSLCert — createHttpClient will try to build an mTLS client
		// with the bad CA bytes and fail.
		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "myaccount",
			ApplianceURL:  "https://conjur.example.com",
			AuthnType:     "cert",
			ServiceID:     "test-cert-service",
			SSLCert:       "not-valid-pem",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
		}

		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("HOME", t.TempDir())

		client, err := NewClientFromEnvironment(config)

		require.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "Can't append Secrets Manager SSL cert")
	})

	t.Run("Returns error when RefreshToken fails (server returns 401)", func(t *testing.T) {
		// newClientFromCertConfig is reached via NewClientFromEnvironment.
		// Simulate: cert auth configured with HTTPS server that rejects with 401.
		unauthorizedServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer unauthorizedServer.Close()

		// Trust the self-signed test server cert.
		certDER := unauthorizedServer.TLS.Certificates[0].Certificate[0]
		serverCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

		certPEM, keyPEM := generateTestCertPEM(t)
		config := Config{
			Account:       "myaccount",
			ApplianceURL:  unauthorizedServer.URL,
			AuthnType:     "cert",
			ServiceID:     "test-cert-service",
			CertHostID:    "vm-01",
			ClientCert:    certPEM,
			ClientCertKey: keyPEM,
			SSLCert:       serverCertPEM,
		}

		e := ClearEnv()
		defer e.RestoreEnv()
		os.Setenv("HOME", t.TempDir())

		client, err := NewClientFromEnvironment(config)

		require.Error(t, err)
		assert.Nil(t, client)
	})
}

func TestNewClientFromEnvironment_CertAuth(t *testing.T) {
	// NewClientFromEnvironment routes to cert auth when config.AuthnType is "cert".
	// The call to newClientFromCertConfig eagerly fetches a token via RefreshToken(),
	// so the mock server must return a parseable Conjur access token.
	t.Run("Uses CertAuthenticator when AuthnType is cert", func(t *testing.T) {
		server, serverCertPEM := mockConjurTLSServerWithCert()
		defer server.Close()

		e := ClearEnv()
		defer e.RestoreEnv()

		certPEM, keyPEM := generateTestCertPEM(t)
		certFile := writeTempFile(t, certPEM)
		keyFile := writeTempFile(t, keyPEM)
		os.Setenv("HOME", t.TempDir())

		config := Config{
			Account:           "myaccount",
			ApplianceURL:      server.URL,
			AuthnType:         "cert",
			ServiceID:         "test-cert-service",
			CertHostID:        "vm-workloads/vm-01",
			ClientCertFile:    certFile,
			ClientCertKeyFile: keyFile,
			SSLCert:           serverCertPEM,
		}

		client, err := NewClientFromEnvironment(config)

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.IsType(t, &authn.CertAuthenticator{}, client.authenticator)
	})
}
