package conjurapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const TestAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
const TestSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func TestClient_CreateIssuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	testCases := []struct {
		name         string
		id           string
		issuerType   string
		maxTTL       int
		data         map[string]interface{}
		assertError  func(*testing.T, error)
		assertIssuer func(*testing.T, Issuer)
	}{
		{
			name:       "Create an Issuer",
			id:         "test-issuer",
			issuerType: "aws",
			maxTTL:     900,
			data: map[string]interface{}{
				"access_key_id":     TestAccessKeyID,
				"secret_access_key": TestSecretAccessKey,
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, "test-issuer", issuer.ID)
				assert.Equal(t, "aws", issuer.Type)
				assert.Equal(t, 900, issuer.MaxTTL)
				assert.Equal(t, TestAccessKeyID, issuer.Data["access_key_id"])
				// Expect masked response for the access key
				assert.Equal(t, "*****", issuer.Data["secret_access_key"])
				assert.NotEmpty(t, issuer.CreatedAt)
				assert.NotEmpty(t, issuer.ModifiedAt)
			},
		},
		{
			name:       "Invalid issuer",
			id:         "test-issuer",
			issuerType: "aws",
			maxTTL:     900,
			data: map[string]interface{}{
				"access_key_id":     "invalid",
				"secret_access_key": "invalid",
			},
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Regexp(
					t,
					// Conjur cloud returns "Entity", Enterprise returns "Content"
					"422 Unprocessable (Content|Entity). invalid 'access_key_id' parameter format",
					err.Error(),
				)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := Issuer{
				ID:     tc.id,
				Type:   tc.issuerType,
				MaxTTL: tc.maxTTL,
				Data:   tc.data,
			}

			createdIssuer, err := conjur.CreateIssuer(issuer)
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuer(t, createdIssuer)

			// Clean up the Issuer, if it was created
			err = conjur.DeleteIssuer(tc.id, false)
			assert.NoError(t, err)
		})
	}
}

func TestClient_DeleteIssuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	testCases := []struct {
		name        string
		id          string
		keepSecrets bool
		setup       func(*testing.T)
		assert      func(*testing.T, error)
	}{
		{
			name:        "Delete an Issuer (Don't keep secrets)",
			id:          "test-issuer",
			keepSecrets: false,
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(
					Issuer{
						ID:     "test-issuer",
						Type:   "aws",
						MaxTTL: 900,
						Data: map[string]interface{}{
							"access_key_id":     TestAccessKeyID,
							"secret_access_key": TestSecretAccessKey,
						},
					},
				)
				assert.NoError(t, err)

				secretPolicy := `
- !variable
  id: dynamic/test-issuer-secret
  annotations:
    dynamic/issuer: test-issuer
    dynamic/method: federation-token
`

				_, err = conjur.LoadPolicy(
					PolicyModePost,
					"data",
					strings.NewReader(secretPolicy),
				)
				assert.NoError(t, err)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)

				exists, err := conjur.ResourceExists(
					"variable:data/dynamic/test-issuer-secret",
				)
				assert.NoError(t, err)
				assert.False(t, exists)
			},
		},
		{
			name:        "Delete an Issuer (Keep secrets)",
			id:          "test-issuer",
			keepSecrets: true,
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(
					Issuer{
						ID:     "test-issuer",
						Type:   "aws",
						MaxTTL: 900,
						Data: map[string]interface{}{
							"access_key_id":     TestAccessKeyID,
							"secret_access_key": TestSecretAccessKey,
						},
					},
				)
				assert.NoError(t, err)

				secretPolicy := `
- !variable
  id: dynamic/test-issuer-secret
  annotations:
    dynamic/issuer: test-issuer
    dynamic/method: federation-token
`

				_, err = conjur.LoadPolicy(
					PolicyModePost,
					"data",
					strings.NewReader(secretPolicy),
				)
				assert.NoError(t, err)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)

				exists, err := conjur.ResourceExists(
					"variable:data/dynamic/test-issuer-secret",
				)
				assert.NoError(t, err)
				assert.True(t, exists)
			},
		},
		{
			name:        "Delete non-existent issuer",
			id:          "test-issuer",
			keepSecrets: true,
			setup:       func(t *testing.T) {},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Regexp(
					t,
					"404 Not Found. Issuer not found.",
					err.Error(),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)

			err := conjur.DeleteIssuer(tc.id, tc.keepSecrets)

			tc.assert(t, err)
		})
	}
}

func TestClient_Issuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	testCases := []struct {
		name         string
		id           string
		setup        func(*testing.T)
		cleanup      func(*testing.T)
		assertError  func(*testing.T, error)
		assertIssuer func(*testing.T, Issuer)
	}{
		{
			name: "Get an Issuer",
			id:   "test-issuer-2",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(
					Issuer{
						ID:     "test-issuer-2",
						Type:   "aws",
						MaxTTL: 900,
						Data: map[string]interface{}{
							"access_key_id":     TestAccessKeyID,
							"secret_access_key": TestSecretAccessKey,
						},
					},
				)
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, "test-issuer-2", issuer.ID)
				assert.Equal(t, "aws", issuer.Type)
				assert.Equal(t, 900, issuer.MaxTTL)
				assert.Equal(t, TestAccessKeyID, issuer.Data["access_key_id"])
				// Expect masked response for the access key
				assert.Equal(t, "*****", issuer.Data["secret_access_key"])
				assert.NotEmpty(t, issuer.CreatedAt)
				assert.NotEmpty(t, issuer.ModifiedAt)
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("test-issuer-2", false)
				assert.NoError(t, err)
			},
		},
		{
			name:    "Get non-existing Issuer",
			id:      "test-issuer",
			setup:   func(t *testing.T) {},
			cleanup: func(t *testing.T) {},
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(
					t,
					"404 Not Found. Issuer not found.",
					err.Error(),
				)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			tc.setup(t)
			defer tc.cleanup(t)

			issuer, err := conjur.Issuer(tc.id)
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuer(t, issuer)
		})
	}
}
