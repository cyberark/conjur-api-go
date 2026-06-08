package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sample_token = `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OSwiZXhwIjo0MTAzMzc5MTY0fQo=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
var expired_token = `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

type rotateAPIKeyTestCase struct {
	name             string
	roleId           string
	login            string
	readResponseBody bool
}

func TestClient_RotateAPIKey(t *testing.T) {
	testCases := []rotateAPIKeyTestCase{
		{
			name:             "Rotate the API key of a foreign role of non-user kind",
			roleId:           "conjur:host:data/test/bob",
			login:            "host/data/test/bob",
			readResponseBody: false,
		},
		{
			name:             "Rotate the API key of a foreign role and read the data stream",
			roleId:           "conjur:host:data/test/bob",
			login:            "host/data/test/bob",
			readResponseBody: true,
		},
		{
			name:             "Rotate the API key of a partially-qualified role and read the data stream",
			roleId:           "host:data/test/bob",
			login:            "host/data/test/bob",
			readResponseBody: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)

			_, err = utils.Setup(utils.DefaultTestPolicy())
			assert.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			runRotateAPIKeyAssertions(t, tc, conjur)
		})
	}
}

func runRotateAPIKeyAssertions(t *testing.T, tc rotateAPIKeyTestCase, conjur *Client) {
	var hostAPIKey []byte
	var err error

	if tc.readResponseBody {
		rotateResponse, e := conjur.RotateAPIKeyReader("conjur:host:data/test/bob")
		assert.NoError(t, e)
		hostAPIKey, err = ReadResponseBody(rotateResponse)
	} else {
		hostAPIKey, err = conjur.RotateAPIKey(tc.roleId)
	}

	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(hostAPIKey)})
	assert.NoError(t, err)
}

var userPolicy = `
- !user alice
`

func TestClient_RotateCurrentUserAPIKey(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Rotate the API key of the current user not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)

			conjur := utils.Client()
			conjur.storage = &mockStorageProvider{}

			_, err = conjur.RotateCurrentUserAPIKey()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Rotate API Key for users is not supported in Idira Secrets Manager, SaaS")
		})
		return
	}

	//TODO: This test is ugly. Refactor it into something more concise.
	t.Run("Rotate the API key of the current user", func(t *testing.T) {
		// SETUP
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)

		keys, err := utils.Setup(userPolicy)
		assert.NoError(t, err)

		// Login as alice with a mock storage provider to store her API key
		config := &Config{}
		config.mergeEnv()
		aliceLogin := testCredential("TEST_LOGIN_ALICE_DATA_TEST")
		aliceAPIKey := keys[aliceLogin]
		conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: aliceLogin, APIKey: aliceAPIKey})
		assert.NoError(t, err)
		conjur.storage = &mockStorageProvider{}
		_, err = conjur.Login(aliceLogin, aliceAPIKey)
		assert.NoError(t, err)

		// EXERCISE
		// This will use the "stored" API key to rotate alice's API key
		newAPIKey, err := conjur.RotateCurrentUserAPIKey()
		assert.NoError(t, err)

		// VERIFY
		// Ensure the new API key works
		_, err = conjur.Authenticate(authn.LoginPair{Login: aliceLogin, APIKey: string(newAPIKey)})
		assert.NoError(t, err)
	})
}

func TestClient_RotateCurrentRoleAPIKey(t *testing.T) {
	t.Run("Rotate the API key of the current host", func(t *testing.T) {
		// SETUP
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)

		hostPolicy := `
- !host
  id: kate
  annotations:
    authn/api-key: true
`

		keys, err := utils.Setup(hostPolicy)
		assert.NoError(t, err)

		config := Config{}
		config.mergeEnv()

		kateLogin := testCredential("TEST_LOGIN_HOST_KATE")
		kateAPIKey := keys["kate"]

		conjur, err := NewClientFromKey(config, authn.LoginPair{Login: kateLogin, APIKey: kateAPIKey})
		require.NoError(t, err)
		conjur.storage = mockStorageWithPreloadedCredentials(kateLogin, kateAPIKey)

		// EXERCISE
		// This will use the "stored" API key to rotate Kate's API key
		newAPIKey, err := conjur.RotateCurrentRoleAPIKey()
		require.NoError(t, err)

		// VERIFY
		// Ensure the new API key works
		_, err = NewClientFromKey(config, authn.LoginPair{Login: kateLogin, APIKey: string(newAPIKey)})
		require.NoError(t, err)
	})
}

type rotateHostAPIKeyTestCase struct {
	name       string
	hostID     string
	login      string
	assertions func(t *testing.T, tc rotateHostAPIKeyTestCase, conjur *Client)
}

func TestClient_RotateHostAPIKey(t *testing.T) {
	testCases := []rotateHostAPIKeyTestCase{
		{
			name:       "Rotate the API key of a foreign host: ID only",
			hostID:     "data/test/bob",
			login:      "host/data/test/bob",
			assertions: runRotateHostAPIKeyAssertions,
		},
		{
			name:       "Rotate the API key of a foreign host: partially qualified",
			hostID:     "host:data/test/bob",
			login:      "host/data/test/bob",
			assertions: runRotateHostAPIKeyAssertions,
		},
		{
			name:       "Rotate the API key of a foreign host: fully qualified",
			hostID:     "conjur:host:data/test/bob",
			login:      "host/data/test/bob",
			assertions: runRotateHostAPIKeyAssertions,
		},
		{
			name:   "Rotate the API key of a foreign host: wrong role kind",
			hostID: "user:data/test/bob",
			assertions: func(t *testing.T, tc rotateHostAPIKeyTestCase, conjur *Client) {
				_, err := conjur.RotateHostAPIKey(tc.hostID)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must represent a host")
			},
		},
		{
			name:   "Rotate the API key of a foreign host: Malformed ID",
			hostID: "id:with:too:many:colons",
			login:  "host/bob",
			assertions: func(t *testing.T, tc rotateHostAPIKeyTestCase, conjur *Client) {
				_, err := conjur.RotateHostAPIKey(tc.hostID)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Malformed ID")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)

			_, err = utils.Setup(utils.DefaultTestPolicy())
			assert.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			tc.assertions(t, tc, conjur)
		})
	}
}

func runRotateHostAPIKeyAssertions(t *testing.T, tc rotateHostAPIKeyTestCase, conjur *Client) {
	var hostAPIKey []byte
	var err error

	hostAPIKey, err = conjur.RotateHostAPIKey(tc.hostID)

	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(hostAPIKey)})
	assert.NoError(t, err)
}

// This is probably redundant with the above test case. Just going to keep them
// separate for expediency for now.
type rotateUserAPIKeyTestCase struct {
	name       string
	userID     string
	login      string
	assertions func(t *testing.T, tc rotateUserAPIKeyTestCase, conjur *Client)
}

func TestClient_RotateUserAPIKey(t *testing.T) {
	aliceLogin := testCredential("TEST_LOGIN_ALICE_DATA_TEST")

	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Rotate the API key of a user not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)

			conjur := utils.Client()
			conjur.storage = &mockStorageProvider{}

			_, err = conjur.RotateUserAPIKey(aliceLogin)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Rotate API Key for users is not supported in Idira Secrets Manager, SaaS")
		})
		return
	}

	testCases := []rotateUserAPIKeyTestCase{
		{
			name:       "Rotate the API key of a user: ID only",
			userID:     aliceLogin,
			login:      aliceLogin,
			assertions: runRotateUserAPIKeyAssertions,
		},
		{
			name:       "Rotate the API key of a user: partially qualified",
			userID:     "user:" + aliceLogin,
			login:      aliceLogin,
			assertions: runRotateUserAPIKeyAssertions,
		},
		{
			name:       "Rotate the API key of a user: fully qualified",
			userID:     "conjur:user:" + aliceLogin,
			login:      aliceLogin,
			assertions: runRotateUserAPIKeyAssertions,
		},
		{
			name:   "Rotate the API key of a user: wrong role kind",
			userID: "host:data/test/bob",
			assertions: func(t *testing.T, tc rotateUserAPIKeyTestCase, conjur *Client) {
				_, err := conjur.RotateUserAPIKey(tc.userID)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must represent a user")
			},
		},
		{
			name:   "Rotate the API key of a user: Malformed ID",
			userID: "id:with:too:many:colons",
			login:  aliceLogin,
			assertions: func(t *testing.T, tc rotateUserAPIKeyTestCase, conjur *Client) {
				_, err := conjur.RotateUserAPIKey(tc.userID)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Malformed ID")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)

			_, err = utils.Setup(userPolicy)
			assert.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			tc.assertions(t, tc, conjur)
		})
	}
}

func runRotateUserAPIKeyAssertions(t *testing.T, tc rotateUserAPIKeyTestCase, conjur *Client) {
	var userAPIKey []byte
	var err error

	userAPIKey, err = conjur.RotateUserAPIKey(tc.userID)

	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(userAPIKey)})
	assert.NoError(t, err)
}

func TestClient_Whoami(t *testing.T) {
	t.Run("Whoami", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)

		conjur := utils.Client()

		resp, err := conjur.WhoAmI()
		assert.NoError(t, err)

		respStr := string(resp)

		assert.Contains(t, respStr, `"account":"conjur"`)
		assert.Contains(t, respStr, `"username":"`+utils.AdminUser()+`"`)
	})
}

func TestClient_ListOidcProviders(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("List OIDC Providers not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			conjur := utils.Client()

			_, err = conjur.ListOidcProviders()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "List OIDC Providers is not supported in Idira Secrets Manager, SaaS")
		})
	} else {
		t.Run("List OIDC Providers", func(t *testing.T) {
			// Mock server to return OIDC providers
			ts, client, _ := createMockConjurClient(t)
			defer ts.Close()

			providers, err := client.ListOidcProviders()
			require.NoError(t, err)

			require.Equal(t, 1, len(providers))
			assert.Equal(t, "test-service-id", providers[0].ServiceID)
		})
	}
}

func TestClient_Login(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		testLoginConjurCloud(t)
	} else {
		testLoginConjurSelfHosted(t)
	}

	t.Run("OIDC authentication", func(t *testing.T) {
		// Mock server to return OIDC token
		ts, client, _ := createMockConjurClient(t)
		defer ts.Close()

		client.config.AuthnType = "oidc"
		client.config.ServiceID = "test-service-id"

		storage, err := createStorageProvider(client.config)
		assert.NoError(t, err)
		client.storage = storage

		token, err := client.OidcAuthenticate("code", "nonce", "code-verifier")
		assert.NoError(t, err)
		assert.Equal(t, "test-token-oidc", string(token))

		// Check that token was cached to the correct location
		contents, err := os.ReadFile(client.GetConfig().NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), client.GetConfig().ApplianceURL+"/authn-oidc/test-service-id")
		assert.Contains(t, string(contents), "test-token-oidc")
	})

	t.Run("JWT authentication", func(t *testing.T) {
		// Mock server to return JWT token
		ts, client, _ := createMockConjurClient(t)
		defer ts.Close()

		client.config.AuthnType = "jwt"
		client.config.ServiceID = "test-service-id"

		token, err := client.JWTAuthenticate("jwt", "")
		assert.NoError(t, err)
		assert.Equal(t, "test-token-jwt", string(token))
	})
}

func TestClient_AuthenticateReader(t *testing.T) {
	t.Run("Retrieves access token reader", func(t *testing.T) {
		// Mock server to return access token
		ts, client, apiKey := createMockConjurClient(t)
		defer ts.Close()

		login := testCredential("TEST_LOGIN_ALICE")
		reader, err := client.AuthenticateReader(authn.LoginPair{
			Login:  login,
			APIKey: apiKey,
		})
		assert.NoError(t, err)
		token, err := ReadResponseBody(reader)
		assert.NoError(t, err)
		assert.Equal(t, "test-token", string(token))
	})
}

func testLoginConjurCloud(t *testing.T) {
	t.Run("Login not supported in Secrets Manager SaaS", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)

		_, err = utils.Setup(utils.DefaultTestPolicy())
		assert.NoError(t, err)
		conjur := utils.Client()

		apiKey, err := conjur.Login(testCredential("TEST_LOGIN_ALICE"), testGeneratedSecret())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Login for users is not supported in Idira Secrets Manager, SaaS")
		assert.Empty(t, apiKey)
	})
}

func testLoginConjurSelfHosted(t *testing.T) {
	// Full test of login and authenticate flow
	t.Run("Login and Authenticate", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		keys, err := utils.Setup(`
- !user cindy
`)
		require.NoError(t, err)

		tempDir := t.TempDir()
		config := &Config{
			NetRCPath: filepath.Join(tempDir, ".netrc"),
		}
		config.mergeEnv()
		conjur, err := NewClient(*config)
		require.NoError(t, err)

		cindyLogin := testCredential("TEST_LOGIN_CINDY_DATA_TEST")
		cindyAPIKey := keys[cindyLogin]
		loginResult, err := conjur.Login(cindyLogin, cindyAPIKey)
		require.NoError(t, err)
		assert.Equal(t, cindyAPIKey, string(loginResult))

		// Check that api key was cached to the correct location
		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL+"/authn")
		assert.Contains(t, string(contents), string(cindyAPIKey))

		// Check that we can authenticate with the cached api key
		authToken, err := conjur.Authenticate(authn.LoginPair{Login: cindyLogin, APIKey: string(loginResult)})
		assert.NoError(t, err)
		assert.NotEmpty(t, string(authToken))
	})
}

type mockStorageProvider struct {
	username              string
	storedCredential      string
	injectError           error
	purgeCalled           bool
	storeCredentialsCalls int
	storeAuthnTokenCalls  int
}

func (m *mockStorageProvider) ReadCredentials() (string, string, error) {
	return m.username, m.storedCredential, m.injectError
}

func (m *mockStorageProvider) StoreCredentials(username, credential string) error {
	m.storeCredentialsCalls++
	m.username = username
	m.storedCredential = credential
	return m.injectError
}

func mockStorageWithPreloadedCredentials(username, credential string) *mockStorageProvider {
	return &mockStorageProvider{
		username:         username,
		storedCredential: credential,
	}
}

func (m *mockStorageProvider) StoreAuthnToken(token []byte) error {
	m.storeAuthnTokenCalls++
	return m.StoreCredentials("", string(token))
}

func mockStorageWithCachedAuthnToken(token string, injectErr error) *mockStorageProvider {
	return &mockStorageProvider{
		storedCredential: token,
		injectError:      injectErr,
	}
}

func (m *mockStorageProvider) ReadAuthnToken() ([]byte, error) {
	_, token, err := m.ReadCredentials()
	return []byte(token), err
}

func (m *mockStorageProvider) PurgeCredentials() error {
	m.purgeCalled = true
	m.username = ""
	m.storedCredential = ""
	return m.injectError
}

func TestClient_PurgeCredentials(t *testing.T) {
	client := &Client{
		config: Config{
			Account:      "conjur",
			ApplianceURL: "https://conjur",
		},
		httpClient: &http.Client{},
		storage:    &mockStorageProvider{},
	}

	t.Run("Calls storage provider's PurgeCredentials", func(t *testing.T) {
		err := client.PurgeCredentials()
		assert.NoError(t, err)
		assert.True(t, client.storage.(*mockStorageProvider).purgeCalled)
	})

	t.Run("Returns error if storage provider returns error", func(t *testing.T) {
		client.storage.(*mockStorageProvider).injectError = errors.New("error")
		err := client.PurgeCredentials()
		assert.EqualError(t, err, "error")
	})

	t.Run("Does nothing if storage provider is nil", func(t *testing.T) {
		client.storage = nil
		err := client.PurgeCredentials()
		assert.NoError(t, err)
	})
}

func TestPurgeCredentials(t *testing.T) {
	// Test the PurgeCredentials function which doesn't require a client

	t.Run("Purges credentials from netrc", func(t *testing.T) {
		tempDir := t.TempDir()
		config := Config{
			Account:           "conjur",
			ApplianceURL:      "https://conjur",
			NetRCPath:         filepath.Join(tempDir, ".netrc"),
			CredentialStorage: "file",
		}

		netrcLogin := testCredential("TEST_NETRC_MACHINE_LOGIN")
		netrcSecret := testCredential("TEST_NETRC_MACHINE_SECRET")
		initialContent := fmt.Sprintf(`
machine https://conjur/authn
	login %s
	password %s`, netrcLogin, netrcSecret)

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		err = PurgeCredentials(config)
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.NotContains(t, string(contents), "https://conjur/authn")
		assert.NotContains(t, string(contents), netrcLogin)
		assert.NotContains(t, string(contents), netrcSecret)
	})

	t.Run("Doesn't fail when not storing credentials", func(t *testing.T) {
		config := Config{
			Account:           "conjur",
			ApplianceURL:      "https://conjur",
			CredentialStorage: "none",
		}
		err := PurgeCredentials(config)
		assert.NoError(t, err)
	})

	t.Run("Returns error for unrecognized storage provider", func(t *testing.T) {
		config := Config{
			Account:           "conjur",
			ApplianceURL:      "https://conjur",
			CredentialStorage: "invalid",
		}
		err := PurgeCredentials(config)
		assert.EqualError(t, err, "Unknown credential storage type")
	})
}

func TestClient_InternalAuthenticate(t *testing.T) {
	config := Config{
		Account:      "conjur",
		ApplianceURL: "https://conjur",
	}

	t.Run("Returns error if no authenticator", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		_, err = client.InternalAuthenticate()
		assert.EqualError(t, err, "unable to authenticate using client without authenticator")
	})

	t.Run("Returns token from authenticator", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		client.authenticator = &authn.TokenAuthenticator{Token: "test-token"}
		token, err := client.InternalAuthenticate()
		assert.NoError(t, err)
		assert.Equal(t, "test-token", string(token))
	})

	t.Run("Returns error if authenticator returns error", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		client.authenticator = &authn.OidcAuthenticator{
			Authenticate: func(code, nonce, code_verifier string) ([]byte, error) {
				return nil, errors.New("error")
			},
		}
		_, err = client.InternalAuthenticate()
		assert.EqualError(t, err, "error")
	})

	t.Run("Returns token when using OIDC", func(t *testing.T) {
		token, err := runOIDCInternalAuthenticateTest(t, sample_token, nil)
		assert.NoError(t, err)
		assert.Equal(t, sample_token, string(token))
	})

	t.Run("Returns re-login message when using OIDC and token is expired", func(t *testing.T) {
		_, err := runOIDCInternalAuthenticateTest(t, expired_token, nil)
		assert.EqualError(t, err, "No valid OIDC token found. Please login again. If this error recurs shortly after logging in, verify your system clock is synchronized.")
	})

	t.Run("Returns error if storage returns error", func(t *testing.T) {
		_, err := runOIDCInternalAuthenticateTest(t, "", errors.New("error"))
		assert.EqualError(t, err, "No valid OIDC token found. Please login again. If this error recurs shortly after logging in, verify your system clock is synchronized.")
	})
}

func TestClient_RefreshToken(t *testing.T) {
	config := Config{
		Account:      "conjur",
		ApplianceURL: "https://conjur",
	}

	t.Run("Updates token from authenticator", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		client.authenticator = &authn.TokenAuthenticator{Token: sample_token}
		err = client.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, sample_token, string(client.authToken.Raw()))
	})

	t.Run("Doesn't update token from authenticator when not required", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		// Set token so that it doesn't need to be refreshed
		client.authToken, err = authn.NewToken([]byte(sample_token))
		assert.NoError(t, err)

		// Change authenticator token so that it doesn't match the token in the client
		client.authenticator = &authn.TokenAuthenticator{Token: "test-token"}

		// Call RefreshToken and verify that the token in the client is not updated
		err = client.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, sample_token, string(client.authToken.Raw()))
	})

	t.Run("Returns error when authenticator returns invalid token", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		client.authenticator = &authn.TokenAuthenticator{Token: "invalid-token"}
		err = client.RefreshToken()
		assert.Error(t, err)
	})

	t.Run("Retrieves cached token when using OIDC", func(t *testing.T) {
		client, err := NewClient(Config{
			Account:      "conjur",
			ApplianceURL: "https://conjur",
			AuthnType:    "oidc",
			ServiceID:    "test-service",
		})
		assert.NoError(t, err)

		client.storage = mockStorageWithCachedAuthnToken(sample_token, nil)
		client.authenticator = &authn.OidcAuthenticator{}
		err = client.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, sample_token, string(client.authToken.Raw()))
	})
}

func TestClient_ForceRefreshToken(t *testing.T) {
	config := Config{
		Account:      "conjur",
		ApplianceURL: "https://conjur",
	}

	t.Run("Forces update of token from authenticator", func(t *testing.T) {
		client, err := NewClient(config)
		assert.NoError(t, err)

		// Set token so that it doesn't need to be refreshed
		client.authToken, err = authn.NewToken([]byte(sample_token))
		assert.NoError(t, err)

		// Change authenticator token so that it doesn't match the token in the client
		client.authenticator = &authn.TokenAuthenticator{Token: expired_token}

		// Call ForceRefreshToken and verify that the token in the client is updated
		err = client.ForceRefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, expired_token, string(client.authToken.Raw()))
	})
}

func runOIDCInternalAuthenticateTest(t *testing.T, token string, injectErr error) ([]byte, error) {
	client, err := NewClient(Config{
		Account:      "conjur",
		ApplianceURL: "https://conjur",
		AuthnType:    "oidc",
		ServiceID:    "test-service",
	})
	assert.NoError(t, err)

	client.storage = mockStorageWithCachedAuthnToken(token, injectErr)
	client.authenticator = &authn.OidcAuthenticator{}
	return client.InternalAuthenticate()
}

type changeUserPasswordTestCase struct {
	name        string
	userID      string
	login       string
	newPassword string
}

func TestClient_ChangeUserPassword(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Change User Password not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			conjur := utils.Client()

			_, err = conjur.ChangeUserPassword(testCredential("TEST_LOGIN_ALICE_DATA_TEST"), testGeneratedSecret(), testGeneratedSecret())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Change User Password is not supported in Idira Secrets Manager, SaaS")
		})
		return
	}

	testCases := []changeUserPasswordTestCase{
		{
			name:        "Change the password of a user",
			userID:      testCredential("TEST_LOGIN_ALICE_DATA_TEST"),
			login:       testCredential("TEST_LOGIN_ALICE_DATA_TEST"),
			newPassword: testCredential("TEST_USER_NEW_PASSWORD"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			config := &Config{
				CredentialStorage: "none",
			}
			utils, err := NewTestUtils(config)
			assert.NoError(t, err)

			_, err = utils.Setup(userPolicy)
			assert.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			runChangeUserPasswordAssertions(t, tc, conjur)
		})
	}
}

func runChangeUserPasswordAssertions(t *testing.T, tc changeUserPasswordTestCase, conjur *Client) {
	var userAPIKey []byte
	var err error

	userAPIKey, err = conjur.RotateUserAPIKey(tc.userID)
	assert.NoError(t, err)

	_, err = conjur.ChangeUserPassword(tc.login, string(userAPIKey), tc.newPassword)
	assert.NoError(t, err)

	userAPIKey, err = conjur.Login(tc.login, tc.newPassword)
	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(userAPIKey)})
	assert.NoError(t, err)
}

type changeCurrentUserPasswordTestCase struct {
	name        string
	newPassword string
}

func TestClient_ChangeCurrentUserPassword(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Change Current User Password not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			conjur := utils.Client()
			conjur.storage = &mockStorageProvider{}

			_, err = conjur.ChangeCurrentUserPassword(testCredential("TEST_USER_CHANGE_CURRENT_PASSWORD"))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Change User Password is not supported in Idira Secrets Manager, SaaS")
		})
		return
	}

	testCases := []changeCurrentUserPasswordTestCase{
		{
			name:        "Change the password of a user",
			newPassword: testCredential("TEST_USER_NEW_PASSWORD"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			tempDir := t.TempDir()
			config := &Config{
				NetRCPath:         filepath.Join(tempDir, ".netrc"),
				CredentialStorage: "file",
			}
			utils, err := NewTestUtils(config)
			assert.NoError(t, err)

			_, err = utils.Setup(userPolicy)
			assert.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			runChangeCurrentUserPasswordAssertions(t, tc, conjur)
		})
	}
}

func runChangeCurrentUserPasswordAssertions(t *testing.T, tc changeCurrentUserPasswordTestCase, conjur *Client) {
	var userAPIKey []byte
	var err error

	aliceLogin := testCredential("TEST_LOGIN_ALICE_DATA_TEST")

	userAPIKey, err = conjur.RotateUserAPIKey(aliceLogin)
	assert.NoError(t, err)

	// Create empty netrc file, then login to write user credentials
	err = os.WriteFile(conjur.config.NetRCPath, []byte(""), 0600)
	assert.NoError(t, err)
	_, err = conjur.Login(aliceLogin, string(userAPIKey))
	assert.NoError(t, err)

	// Change the user password, then login + authenticate to test the new password
	_, err = conjur.ChangeCurrentUserPassword(tc.newPassword)
	assert.NoError(t, err)

	userAPIKey, err = conjur.Login(aliceLogin, tc.newPassword)
	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: aliceLogin, APIKey: string(userAPIKey)})
	assert.NoError(t, err)
}

var publicKeysTestPolicy = `
- !user
  id: alice
  public_keys:
  - ssh-rsa test-key-1 laptop
  - ssh-rsa test-key-2 workstation
`

type publicKeysTestCase struct {
	name       string
	kind       string
	identifier string
}

func TestClient_PublicKeys(t *testing.T) {
	aliceLogin := testCredential("TEST_LOGIN_ALICE_DATA_TEST")

	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Display public keys not supported in Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			conjur := utils.Client()

			_, err = conjur.PublicKeys("user", aliceLogin)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Public Keys is not supported in Idira Secrets Manager, SaaS")
		})
		return
	}

	testCases := []publicKeysTestCase{
		{
			name:       "Display public keys",
			kind:       "user",
			identifier: aliceLogin,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			config := &Config{
				CredentialStorage: "none",
			}
			utils, err := NewTestUtils(config)
			require.NoError(t, err)

			_, err = utils.Setup(publicKeysTestPolicy)
			require.NoError(t, err)
			conjur := utils.Client()

			// EXERCISE
			runPublicKeysAssertions(t, tc, conjur)
		})
	}
}

func runPublicKeysAssertions(t *testing.T, tc publicKeysTestCase, conjur *Client) {
	publicKeys, err := conjur.PublicKeys(tc.kind, tc.identifier)
	if err != nil && strings.Contains(err.Error(), "public keys endpoint is not available on this server") {
		t.Skip("Conjur server does not support the public_keys endpoint")
	}
	require.NoError(t, err)

	expectedOutput := "ssh-rsa test-key-1 laptop\nssh-rsa test-key-2 workstation\n"
	assert.Equal(t, expectedOutput, string(publicKeys))
}

var jwtAuthenticatorPolicy = `
- !policy
  id: test
  body:
  - !webservice
  - !variable public-keys
  - !variable issuer
  - !variable audience
  - !variable token-app-property
  - !variable identity-path
  - !webservice status
  - !group authenticatable
  - !permit
    role: !group authenticatable
    privilege: [ read, authenticate ]
    resource: !webservice
  - !grant
    role: !group authenticatable
    member: !host /data/test/jwt-apps/workload@example.com
`

var jwtRolePolicy = `
- !policy
  id: jwt-apps
  body:
  - !host
    id: workload@example.com
    annotations:
      authn-jwt/test/sub: test-workload
`

func TestClient_JwtAuthenticate(t *testing.T) {
	t.Run("With a valid authn-jwt config", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		err = utils.SetupWithAuthenticator("jwt", jwtAuthenticatorPolicy, jwtRolePolicy)
		require.NoError(t, err)
		conjur := utils.Client()

		// Construct the jwks string
		jwks := "{\"type\":\"jwks\",\"value\":" + os.Getenv("PUBLIC_KEYS") + "}"

		conjur.AddSecret("conjur/authn-jwt/test/public-keys", jwks)
		conjur.AddSecret("conjur/authn-jwt/test/issuer", "jwt-server")
		conjur.AddSecret("conjur/authn-jwt/test/audience", "conjur")
		conjur.AddSecret("conjur/authn-jwt/test/token-app-property", "email")
		conjur.AddSecret("conjur/authn-jwt/test/identity-path", "data/test/jwt-apps")

		authnType := "jwt"
		serviceID := "test"

		err = conjur.EnableAuthenticator(authnType, serviceID, true)
		require.NoError(t, err)

		t.Run("Successfully creates a client", func(t *testing.T) {
			conjur, err = NewClientFromJwt(Config{
				Account:      "conjur",
				ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
				AuthnType:    authnType,
				ServiceID:    serviceID,
				JWTContent:   os.Getenv("JWT"),
			})
			require.NoError(t, err)

			t.Run("Successfully authenticates with the client", func(t *testing.T) {
				_, err := conjur.authenticator.RefreshToken()
				require.NoError(t, err)

				resp, err := conjur.WhoAmI()
				require.NoError(t, err)
				assert.Contains(t, string(resp), fmt.Sprintf(`"username":"%s"`, "host/data/test/jwt-apps/workload@example.com"))
			})
		})
	})
}

func TestClient_OidcTokenAuthenticate(t *testing.T) {
	// This test currently only runs against Secrets Manager SaaS, where we have a valid OIDC token
	// from Identity.
	if os.Getenv("IDENTITY_TOKEN") == "" {
		t.Skip("IDENTITY_TOKEN is not set")
	}
	t.Run("Successfully creates a client", func(t *testing.T) {
		authnType := "oidc"
		serviceID := "cyberark"

		conjur, err := NewClientFromOidcToken(Config{
			Account:      "conjur",
			ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
			AuthnType:    authnType,
			ServiceID:    serviceID,
		}, os.Getenv("IDENTITY_TOKEN"))
		require.NoError(t, err)

		t.Run("Successfully authenticates with the client", func(t *testing.T) {
			_, err := conjur.authenticator.RefreshToken()
			require.NoError(t, err)

			resp, err := conjur.WhoAmI()
			require.NoError(t, err)
			assert.Contains(t, string(resp), fmt.Sprintf(`"username":"%s"`, os.Getenv("CONJUR_AUTHN_LOGIN")))
		})
	})
}

func TestClient_CloudHostLogin(t *testing.T) {
	hostLogin := testCredential("TEST_LOGIN_HOST_TEST")

	t.Run("Successful authentication via Authenticate endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("mock-access-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL: server.URL,
			Account:      "conjur",
		}

		client, err := NewClient(config)
		require.NoError(t, err)

		mockStorage := &mockStorageProvider{}
		client.storage = mockStorage

		hostAPIKey := testGeneratedSecret()
		apiKey, err := client.CloudHostLogin(hostLogin, hostAPIKey)

		assert.NoError(t, err)
		assert.Equal(t, hostAPIKey, string(apiKey))
		assert.Equal(t, hostLogin, mockStorage.username)
		_, storedCredential, err := mockStorage.ReadCredentials()
		assert.NoError(t, err)
		assert.Equal(t, hostAPIKey, storedCredential)
	})

	t.Run("Returns error when authentication fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid credentials"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL: server.URL,
			Account:      "conjur",
		}

		client, err := NewClient(config)
		require.NoError(t, err)

		apiKey, err := client.CloudHostLogin(hostLogin, testGeneratedSecret())

		assert.Error(t, err)
		assert.Nil(t, apiKey)
		assert.Contains(t, err.Error(), "unable to authenticate with Idira Secrets Manager")
	})

	t.Run("Handles storage errors gracefully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("mock-access-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL: server.URL,
			Account:      "conjur",
		}

		client, err := NewClient(config)
		require.NoError(t, err)

		mockStorage := &mockStorageProvider{injectError: assert.AnError}
		client.storage = mockStorage

		apiKey, err := client.CloudHostLogin(hostLogin, testGeneratedSecret())

		assert.Error(t, err)
		assert.Nil(t, apiKey)
		assert.Contains(t, err.Error(), "failed to store credentials")
	})

	t.Run("Works without storage provider", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("mock-access-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL: server.URL,
			Account:      "conjur",
		}

		client, err := NewClient(config)
		require.NoError(t, err)
		client.storage = nil

		hostAPIKey := testGeneratedSecret()
		apiKey, err := client.CloudHostLogin(hostLogin, hostAPIKey)

		assert.NoError(t, err)
		assert.Equal(t, hostAPIKey, string(apiKey))
	})

	t.Run("ReadOnly mode does not store credentials", func(t *testing.T) {
		t.Setenv(credentialStorageModeEnvVar, "readonly")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/authenticate") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("mock-access-token"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := Config{
			ApplianceURL: server.URL,
			Account:      "conjur",
		}

		client, err := NewClient(config)
		require.NoError(t, err)

		mockStorage := &mockStorageProvider{}
		client.storage = mockStorage

		hostAPIKey := testGeneratedSecret()
		apiKey, err := client.CloudHostLogin(hostLogin, hostAPIKey)

		assert.NoError(t, err)
		assert.Equal(t, hostAPIKey, string(apiKey))
		assert.Equal(t, 0, mockStorage.storeCredentialsCalls)
	})

	t.Run("ReadOnly mode still allows purge", func(t *testing.T) {
		storedLogin := testGeneratedSecret()
		mock := &mockStorageProvider{username: storedLogin}
		mock.StoreCredentials(storedLogin, testGeneratedSecret())
		client := &Client{
			config:  Config{CredentialStorageMode: CredentialStorageModeReadOnly},
			storage: mock,
		}

		err := client.PurgeCredentials()
		assert.NoError(t, err)
		assert.True(t, mock.purgeCalled)
	})

	t.Run("ReadOnly mode allows reading stored credentials", func(t *testing.T) {
		storedLogin := testGeneratedSecret()
		storedCredential := testGeneratedSecret()
		mock := &mockStorageProvider{username: storedLogin}
		mock.StoreCredentials(storedLogin, storedCredential)
		mock.storeCredentialsCalls = 0
		client := &Client{
			config:  Config{CredentialStorageMode: CredentialStorageModeReadOnly},
			storage: mock,
		}

		login, credential, err := client.storage.ReadCredentials()
		assert.NoError(t, err)
		assert.Equal(t, storedLogin, login)
		assert.Equal(t, storedCredential, credential)
		assert.Equal(t, 0, mock.storeCredentialsCalls)

		token, err := client.storage.ReadAuthnToken()
		assert.NoError(t, err)
		assert.Equal(t, []byte(storedCredential), token)
	})
}

func TestClient_credentialStorageMode_writeSuppression(t *testing.T) {
	t.Run("zero-value mode allows writes", func(t *testing.T) {
		mock := &mockStorageProvider{}
		client := &Client{
			config:  Config{},
			storage: mock,
		}

		err := client.storeCredentialsIfAvailable(testGeneratedSecret(), testGeneratedSecret())
		assert.NoError(t, err)
		assert.Equal(t, 1, mock.storeCredentialsCalls)
	})

	t.Run("Login skips writes in ReadOnly mode", func(t *testing.T) {
		apiKey := testGeneratedSecret()
		login := testCredential("TEST_LOGIN_ALICE")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/authn/conjur/login") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(apiKey))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		mock := &mockStorageProvider{}
		client := &Client{
			config: Config{
				ApplianceURL:          server.URL,
				Account:               "conjur",
				CredentialStorageMode: CredentialStorageModeReadOnly,
			},
			httpClient: server.Client(),
			storage:    mock,
		}

		result, err := client.Login(login, testGeneratedSecret())
		assert.NoError(t, err)
		assert.Equal(t, apiKey, string(result))
		assert.Equal(t, 0, mock.storeCredentialsCalls)
	})

	t.Run("storeCredentialsIfAvailable skips writes in ReadOnly mode", func(t *testing.T) {
		mock := &mockStorageProvider{}
		client := &Client{
			config:  Config{CredentialStorageMode: CredentialStorageModeReadOnly},
			storage: mock,
		}

		err := client.storeCredentialsIfAvailable(testGeneratedSecret(), testGeneratedSecret())
		assert.NoError(t, err)
		assert.Equal(t, 0, mock.storeCredentialsCalls)
	})

	t.Run("storeCredentialsIfAvailable writes in ReadWrite mode", func(t *testing.T) {
		mock := &mockStorageProvider{}
		client := &Client{
			config:  Config{CredentialStorageMode: CredentialStorageModeReadWrite},
			storage: mock,
		}

		err := client.storeCredentialsIfAvailable(testGeneratedSecret(), testGeneratedSecret())
		assert.NoError(t, err)
		assert.Equal(t, 1, mock.storeCredentialsCalls)
	})

	t.Run("authenticateWithTokenStorage skips writes in ReadOnly mode", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("token-bytes"))
		}))
		defer server.Close()

		mock := &mockStorageProvider{}
		client := &Client{
			config:     Config{CredentialStorageMode: CredentialStorageModeReadOnly},
			httpClient: server.Client(),
			storage:    mock,
		}

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		token, err := client.authenticateWithTokenStorage(req)
		assert.NoError(t, err)
		assert.Equal(t, []byte("token-bytes"), token)
		assert.Equal(t, 0, mock.storeAuthnTokenCalls)
	})
}
