package conjurapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientV2_BatchRetrieveSecretsSafe(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(batchSecretsTestPolicy)
	require.NoError(t, err)
	conjur := utils.Client().V2()
	if !conjur.config.IsSaaS() {
		t.Skip("Skipping V2 Batch Retrieve Secrets test for on-prem")
	}

	text := utils.IDWithPath("secret1")
	binary := utils.IDWithPath("secret2")
	missing := utils.IDWithPath("nonexistent")
	// Not valid UTF-8, so the server can only return it base64-encoded.
	binaryValue := "\x00\xff\xfe binary"
	require.NoError(t, utils.Client().AddSecret(text, "value1"))
	require.NoError(t, utils.Client().AddSecret(binary, binaryValue))

	byID := func(t *testing.T, response *BatchSecretResponse) map[string]SecretValue {
		t.Helper()
		secrets := make(map[string]SecretValue)
		for _, secret := range response.Secrets {
			secrets[secret.ID] = secret
		}
		return secrets
	}

	t.Run("Returns text and binary values as they were stored", func(t *testing.T) {
		response, err := conjur.BatchRetrieveSecretsSafe([]string{text, binary, missing})
		require.NoError(t, err)
		secrets := byID(t, response)
		require.Len(t, secrets, 3)

		assert.Equal(t, http.StatusOK, secrets[text].Status)
		assert.Equal(t, "value1", secrets[text].Value)
		assert.Equal(t, http.StatusOK, secrets[binary].Status)
		assert.Equal(t, binaryValue, secrets[binary].Value)
		assert.Equal(t, http.StatusNotFound, secrets[missing].Status)
		assert.Empty(t, secrets[missing].Value)
	})

	t.Run("BatchRetrieveSecrets can't return the binary value", func(t *testing.T) {
		response, err := conjur.BatchRetrieveSecrets([]string{text, binary})
		require.NoError(t, err)
		secrets := byID(t, response)

		assert.Equal(t, "value1", secrets[text].Value)
		assert.Equal(t, http.StatusNotAcceptable, secrets[binary].Status)
		assert.Empty(t, secrets[binary].Value)
	})
}
