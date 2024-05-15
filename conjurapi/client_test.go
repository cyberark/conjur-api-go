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

		assert.NoError(t, err)
		assert.IsType(t, &authn.APIKeyAuthenticator{}, client.authenticator)
	})
}

func TestClient_GetConfig(t *testing.T) {
	t.Run("Returns Client Config", func(t *testing.T) {
		expectedConfig := Config{
			Account:      "some-account",
			ApplianceURL: "some-appliance-url",
			NetRCPath:    "some-netrc-path",
			SSLCert:      "some-ssl-cert",
			SSLCertPath:  "some-ssl-cert-path",
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

		assert.NoError(t, err)
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
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		t.Setenv("CONJUR_AUTHN_TOKEN_FILE", "token-file")
		client, err := NewClientFromEnvironment(config)
		assert.NoError(t, err)
		assert.IsType(t, &authn.TokenFileAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromToken when CONJUR_AUTHN_TOKEN is set", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		t.Setenv("CONJUR_AUTHN_TOKEN", "some-token")
		client, err := NewClientFromEnvironment(config)
		assert.NoError(t, err)
		assert.IsType(t, &authn.TokenAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromJwt when CONJUR_AUTHN_JWT_SERVICE is set", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		t.Setenv("CONJUR_AUTHN_JWT_SERVICE_ID", "jwt-service")
		client, err := NewClientFromEnvironment(config)
		assert.NoError(t, err)
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)
	})
	t.Run("Calls NewClientFromKey with when LoginPair is retrieved from env variables", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "appliance-url"}
		t.Setenv("CONJUR_AUTHN_LOGIN", "user")
		t.Setenv("CONJUR_AUTHN_API_KEY", "password")
		client, err := NewClientFromEnvironment(config)
		assert.NoError(t, err)
		assert.IsType(t, &authn.APIKeyAuthenticator{}, client.authenticator)
	})

	t.Run("Returns error when config is invalid", func(t *testing.T) {
		config := Config{Account: ""}
		client, err := NewClientFromEnvironment(config)
		assert.ErrorContains(t, err, "Must specify an Account")
		assert.Nil(t, client)
	})

	t.Run("Returns error when no credentials found", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "appliance-url", CredentialStorage: "none"}
		t.Setenv("CONJUR_AUTHN_LOGIN", "")
		t.Setenv("CONJUR_AUTHN_API_KEY", "")

		client, err := NewClientFromEnvironment(config)
		assert.EqualError(t, err, "No valid credentials found. Please login again.")
		assert.Nil(t, client)
	})

	t.Run("Returns error when using nonexistent SSLCertPath", func(t *testing.T) {
		t.Setenv("CONJUR_AUTHN_LOGIN", "user")
		t.Setenv("CONJUR_AUTHN_API_KEY", "password")
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
		assert.NotNil(t, client)

		// Verify that the client authenticator is of type TokenAuthenticator
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)

		// Expect it to fail without a mocked JWT server
		token, err := client.authenticator.(*authn.JWTAuthenticator).RefreshToken()
		assert.Error(t, err)
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
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)

		// Verify that the JWT authenticator succeeds
		token, err := client.authenticator.(*authn.JWTAuthenticator).RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, "test-access-token", string(token))
	})

	t.Run("Fetches JWT from file", func(t *testing.T) {
		// Listen for JWT authentication requests
		mockConjurServer := mockConjurServerWithJWT()
		defer mockConjurServer.Close()

		tempDir := t.TempDir()
		err := os.WriteFile(tempDir+"/jwt-token", []byte("jwt-token"), 0644)
		assert.NoError(t, err)

		config := Config{
			Account:      "myaccount",
			ApplianceURL: mockConjurServer.URL,
			AuthnType:    "jwt",
			ServiceID:    "jwt-service",
			JWTFilePath:  tempDir + "/jwt-token",
		}

		client, err := NewClientFromJwt(config)
		assert.NoError(t, err)
		assert.NotNil(t, client)

		// Verify that the client authenticator is of type TokenAuthenticator
		assert.IsType(t, &authn.JWTAuthenticator{}, client.authenticator)
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
		assert.NoError(t, err)

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
		assert.NotNil(t, client)

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

		assert.NoError(t, err)
		assert.IsType(t, &authn.TokenAuthenticator{}, client.authenticator)
	})
}

func TestNewClientFromOidcCode(t *testing.T) {
	t.Run("Has authenticator of type OidcAuthenticator", func(t *testing.T) {
		config := Config{ServiceID: "test", AuthnType: "oidc", Account: "account", ApplianceURL: "appliance-url"}
		client, err := NewClientFromOidcCode(config, "test-code", "test-nonce", "test-code-verifier")

		assert.NoError(t, err)
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
		if storageProvider, _ := createStorageProvider(config); storageProvider != nil {
			storageProvider.StoreCredentials("user", "password")
		}
		client, err := newClientFromStoredCredentials(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
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

		assert.EqualError(t, err, "Can't append Conjur SSL cert")
		assert.Nil(t, client)
	})
	t.Run("New HTTPS client with valid cert", func(t *testing.T) {
		config := Config{}
		client, err := newHTTPSClient([]byte(sample_cert), config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestClient_HttpClientTimeoutValue(t *testing.T) {
	t.Run("Create HTTP client with default timeout value", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url"}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, time.Second*time.Duration(HttpTimeoutDefaultValue), client.Timeout)
	})
	t.Run("Create HTTP client with no timeout", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url", HttpTimeout: -1}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, time.Second*time.Duration(0), client.Timeout)
	})
	t.Run("Create HTTP client with specific timeout", func(t *testing.T) {
		config := Config{Account: "account", ApplianceURL: "http://appliance-url", HttpTimeout: 5}
		client, err := createHttpClient(config)

		assert.NoError(t, err)
		assert.NotNil(t, client)
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
