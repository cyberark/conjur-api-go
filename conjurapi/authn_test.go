package conjurapi

import (
	"os"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
)

type testCase struct {
	name             string
	roleId           string
	login            string
	readResponseBody bool
}

func TestClient_RotateAPIKey(t *testing.T) {
	testCases := []testCase{
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

	t.Run("V5", func(t *testing.T) {

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// SETUP
				conjur, err := v5Setup()
				assert.NoError(t, err)

				// EXERCISE
				runAssertions(t, tc, conjur)
			})
		}
	})

	if os.Getenv("TEST_VERSION") != "oss" {
		t.Run("V4", func(t *testing.T) {

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					// SETUP
					conjur, err := v4Setup()
					assert.NoError(t, err)

					// EXERCISE
					runAssertions(t, tc, conjur)
				})

			}
		})
	}
}

func runAssertions(t *testing.T, tc testCase, conjur *Client) {
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
