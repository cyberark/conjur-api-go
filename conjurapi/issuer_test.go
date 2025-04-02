package conjurapi

import (
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
		})
	}
}
