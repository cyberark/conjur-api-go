package conjurapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestClient_OidcAuthenticate(t *testing.T) {
	testCases := []struct {
		name                 string
		tokenPath            string
		expectFileWriteError bool
	}{
		{
			name:      "Caches token to default location",
			tokenPath: "",
		},
		{
			name:      "Caches token to custom location",
			tokenPath: t.TempDir() + "/tmp/test-token",
		},
		{
			// Writing this file will fail but there should be no error returned from OidcAuthenticate()
			name:                 "Caches token to custom location with trailing slash",
			tokenPath:            t.TempDir() + "/tmp/test-token/",
			expectFileWriteError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts, client := setupTestOidcClient(tc.tokenPath)
			defer ts.Close()

			token, err := client.OidcAuthenticate("code", "nonce", "code-verifier")

			assert.NoError(t, err)
			assert.Equal(t, "test-token", string(token))

			if tc.expectFileWriteError {
				// File writing should have failed, so the token should not have been cached
				// We just want to test that there was no error returned from OidcAuthenticate()
				return
			}

			// Check that token was cached to the correct location
			var tokenPath string
			if tc.tokenPath == "" {
				tokenPath = defaultOidcTokenPath
			} else {
				tokenPath = tc.tokenPath
			}

			// Check file permissions
			fileInfo, err := os.Stat(tokenPath)
			assert.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm())

			// Check file contents
			tokenFile, err := os.Open(tokenPath)
			assert.NoError(t, err)

			tokenBytes, err := io.ReadAll(tokenFile)
			assert.NoError(t, err)
			assert.Equal(t, "test-token", string(tokenBytes))

			// Cleanup
			os.Remove(tokenPath)
		})
	}
}

func setupTestOidcClient(tokenPath string) (*httptest.Server, *Client) {
	mockConjurServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Listen for the authenticate endpoint and return a test token
		if strings.HasSuffix(r.URL.Path, "/authn-oidc/test-provider/cucumber/authenticate") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-token"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	client := &Client{
		config: Config{
			Account:       "cucumber",
			ApplianceURL:  mockConjurServer.URL,
			AuthnType:     "oidc",
			ServiceID:     "test-provider",
			OidcTokenPath: tokenPath,
		},
		httpClient: &http.Client{},
	}

	return mockConjurServer, client
}
