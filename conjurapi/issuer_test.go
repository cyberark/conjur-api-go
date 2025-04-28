package conjurapi

import (
	"fmt"
	"os"
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

func TestClient_Issuers(t *testing.T) {
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
		assertIssuers func(*testing.T, []Issuer)
	}{
		{
			name: "No issuers ever created",
			setup: func(t *testing.T) {
			},
			assertError: func(t *testing.T, err error) {
				if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
					// In Conjur Cloud, the issuer branch is pre-created
					assert.NoError(t, err)
				} else {
					// In this case, the Issuer policy doesn't yet exist
					// so we expect a 403 Forbidden error
					assert.Error(t, err, "403 Forbidden")
				}
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
					assert.Empty(t, issuers)
				}
			},
			cleanup: func(t *testing.T) {
			},
		},
		{
			name: "No current issuers",
			setup: func(t *testing.T) {
				// Create and delete an issuer to ensure that the
				// issuer policy exists, but there are no current issuers
				// in the system.
				issuer := Issuer{
					ID:     "no-current-issuer",
					Type:   "aws",
					MaxTTL: 900,
					Data: map[string]interface{}{
						"access_key_id":     TestAccessKeyID,
						"secret_access_key": TestSecretAccessKey,
					},
				}

				issuer, err := conjur.CreateIssuer(issuer)
				assert.NoError(t, err)

				err = conjur.DeleteIssuer(issuer.ID, false)
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Empty(t, issuers)
			},
			cleanup: func(t *testing.T) {
			},
		},
		{
			name: "Single issuer",
			setup: func(t *testing.T) {
				// Create and delete an issuer to ensure that the
				// issuer policy exists, but there are no current issuers
				// in the system.
				issuer := Issuer{
					ID:     "single-issuer",
					Type:   "aws",
					MaxTTL: 900,
					Data: map[string]interface{}{
						"access_key_id":     TestAccessKeyID,
						"secret_access_key": TestSecretAccessKey,
					},
				}

				_, err := conjur.CreateIssuer(issuer)
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Len(t, issuers, 1)
			},
			cleanup: func(t *testing.T) {
				err = conjur.DeleteIssuer("single-issuer", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "100 issuers",
			setup: func(t *testing.T) {
				for i := 0; i < 100; i++ {
					issuer := Issuer{
						ID:     fmt.Sprintf("issuer-%d", i),
						Type:   "aws",
						MaxTTL: 900,
						Data: map[string]interface{}{
							"access_key_id":     TestAccessKeyID,
							"secret_access_key": TestSecretAccessKey,
						},
					}

					_, err := conjur.CreateIssuer(issuer)
					assert.NoError(t, err)
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Len(t, issuers, 100)
			},
			cleanup: func(t *testing.T) {
				for i := 0; i < 100; i++ {
					err = conjur.DeleteIssuer(fmt.Sprintf("issuer-%d", i), false)
					assert.NoError(t, err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			tc.setup(t)
			defer tc.cleanup(t)

			issuers, err := conjur.Issuers()
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuers(t, issuers)
		})
	}
}