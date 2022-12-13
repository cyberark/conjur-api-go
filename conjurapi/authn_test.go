package conjurapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
)

type rotateAPIKeyTestCase struct {
	name             string
	roleId           string
	login            string
	readResponseBody bool
}

func TestClient_RotateAPIKey(t *testing.T) {
	testCases := []rotateAPIKeyTestCase{
		{
			name:             "Rotate the API key of a foreign user role of kind user",
			roleId:           "cucumber:user:alice",
			login:            "alice",
			readResponseBody: false,
		},
		{
			name:             "Rotate the API key of a foreign role of non-user kind",
			roleId:           "cucumber:host:bob",
			login:            "host/bob",
			readResponseBody: false,
		},
		{
			name:             "Rotate the API key of a foreign role and read the data stream",
			roleId:           "cucumber:user:alice",
			login:            "alice",
			readResponseBody: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			conjur, err := conjurSetup()
			assert.NoError(t, err)

			// EXERCISE
			runRotateAPIKeyAssertions(t, tc, conjur)
		})
	}
}

func runRotateAPIKeyAssertions(t *testing.T, tc rotateAPIKeyTestCase, conjur *Client) {
	var userApiKey []byte
	var err error

	if tc.readResponseBody {
		rotateResponse, e := conjur.RotateAPIKeyReader("cucumber:user:alice")
		assert.NoError(t, e)
		userApiKey, err = ReadResponseBody(rotateResponse)
	} else {
		userApiKey, err = conjur.RotateAPIKey(tc.roleId)
	}

	assert.NoError(t, err)

	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(userApiKey)})
	assert.NoError(t, err)
}

type rotateHostAPIKeyTestCase struct {
	name   string
	hostID string
	login  string
}

func TestClient_RotateHostAPIKey(t *testing.T) {
	testCases := []rotateHostAPIKeyTestCase{
		{
			name:   "Rotate the API key of a foreign host",
			hostID: "bob",
			login:  "host/bob",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			conjur, err := conjurSetup()
			assert.NoError(t, err)

			// EXERCISE
			runRotateHostAPIKeyAssertions(t, tc, conjur)
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
	name   string
	userID string
	login  string
}

func TestClient_RotateUserAPIKey(t *testing.T) {
	testCases := []rotateUserAPIKeyTestCase{
		{
			name:   "Rotate the API key of a user",
			userID: "alice",
			login:  "alice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			conjur, err := conjurSetup()
			assert.NoError(t, err)

			// EXERCISE
			runRotateUserAPIKeyAssertions(t, tc, conjur)
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

func TestClient_Login(t *testing.T) {
	t.Run("Login and Authenticate", func(t *testing.T) {
		ts, client := setupTestClient(t)
		defer ts.Close()

		token, err := client.Login("alice", "password")
		assert.NoError(t, err)
		assert.Equal(t, "test-api-key", string(token))

		// Check that api key was cached to the correct location
		contents, err := os.ReadFile(client.GetConfig().NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), client.GetConfig().ApplianceURL+"/authn")
		assert.Contains(t, string(contents), "test-api-key")

		// Check that we can authenticate with the cached api key
		token, err = client.Authenticate(authn.LoginPair{Login: "alice", APIKey: string(token)})
		assert.NoError(t, err)
		assert.Equal(t, "test-token", string(token))
	})

	t.Run("OIDC authentication", func(t *testing.T) {
		ts, client := setupTestClient(t)
		defer ts.Close()

		client.config.AuthnType = "oidc"
		client.config.ServiceID = "test-service-id"

		token, err := client.OidcAuthenticate("code", "nonce", "code-verifier")
		assert.NoError(t, err)
		assert.Equal(t, "test-token-oidc", string(token))

		// Check that token was cached to the correct location
		contents, err := os.ReadFile(client.GetConfig().NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), client.GetConfig().ApplianceURL+"/authn-oidc/test-service-id")
		assert.Contains(t, string(contents), "test-token-oidc")
	})
}

func TestClient_PurgeCredentials(t *testing.T) {
	config := setupConfig(t)

	t.Run("Removes machine if it exists", func(t *testing.T) {
		initialContent := `
machine http://conjur/authn
	login admin
	password password`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		err = PurgeCredentials(config)
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.NotContains(t, string(contents), config.ApplianceURL)
	})

	t.Run("Does not error if machine does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)
		_, err := os.Create(config.NetRCPath)
		assert.NoError(t, err)

		err = PurgeCredentials(config)
		assert.NoError(t, err)
	})

	t.Run("Does not error if file does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		err := PurgeCredentials(config)
		assert.NoError(t, err)
	})
}

func setupTestClient(t *testing.T) (*httptest.Server, *Client) {
	mockConjurServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Listen for the login, authenticate, and oidc endpoints and return test values
		if strings.HasSuffix(r.URL.Path, "/authn/cucumber/login") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-api-key"))
		} else if strings.HasSuffix(r.URL.Path, "/authn/cucumber/alice/authenticate") {
			// Ensure that the api key we returned in /login is being used
			body, _ := io.ReadAll(r.Body)
			if string(body) == "test-api-key" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test-token"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else if strings.HasSuffix(r.URL.Path, "/authn-oidc/test-service-id/cucumber/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-token-oidc"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	tempDir := t.TempDir()
	client := &Client{
		config: Config{
			Account:      "cucumber",
			ApplianceURL: mockConjurServer.URL,
			NetRCPath:    filepath.Join(tempDir, ".netrc"),
		},
		httpClient: &http.Client{},
	}

	return mockConjurServer, client
}

type changeUserPasswordTestCase struct {
	name string
	userID string
	login string
	newPassword string
}

func TestClient_ChangeUserPassword(t *testing.T) {
	testCases := []changeUserPasswordTestCase{
		{
			name:   "Change the password of a user",
			userID: "alice",
			login: "alice",
			newPassword: "SUp3r$3cr3t!!",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// SETUP
			conjur, err := conjurSetup()
			assert.NoError(t, err)

			// EXERCISE
			runChangeUserPasswordAssertions(t, tc, conjur)
		})
	}
}

func runChangeUserPasswordAssertions(t *testing.T, tc changeUserPasswordTestCase, conjur *Client) {
	var userAPIKey []byte
	var err error

	userAPIKey, err = conjur.RotateUserAPIKey(tc.userID)
	
	_, err = conjur.ChangeUserPassword(tc.login, string(userAPIKey), tc.newPassword)
	assert.NoError(t, err)

	userAPIKey, err = conjur.Login(tc.login, tc.newPassword)
	assert.NoError(t, err)
	
	_, err = conjur.Authenticate(authn.LoginPair{Login: tc.login, APIKey: string(userAPIKey)})
	assert.NoError(t, err)
}
