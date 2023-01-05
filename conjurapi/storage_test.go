package conjurapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreCredentials(t *testing.T) {
	config := setupConfig(t)

	t.Run("Creates file if it does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		err := storeCredentials(config, "login", "apiKey")
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL+"/authn")
		assert.Contains(t, string(contents), "apiKey")
	})

	t.Run("Creates machine if it does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)
		_, err := os.Create(config.NetRCPath)
		assert.NoError(t, err)

		err = storeCredentials(config, "login", "apiKey")
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL+"/authn")
		assert.Contains(t, string(contents), "apiKey")
	})

	t.Run("Updates machine if it exists", func(t *testing.T) {
		os.Remove(config.NetRCPath)
		initialContent := `
machine http://conjur/authn
	login admin
	password password`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		err = storeCredentials(config, "login", "apiKey")
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL)
		assert.Contains(t, string(contents), "apiKey")
	})

	t.Run("Uses authn type in machine url", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		oidcConfig := Config{
			ApplianceURL: config.ApplianceURL,
			NetRCPath:    config.NetRCPath,
			AuthnType:    "oidc",
			ServiceID:    "my-service",
		}

		err := storeCredentials(oidcConfig, "[oidc]", "token-contents")
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL+"/authn-oidc/my-service")
		assert.Contains(t, string(contents), "token-contents")
	})
}

func TestReadCachedAccessToken(t *testing.T) {
	config := setupConfig(t)
	config.AuthnType = "oidc"
	config.ServiceID = "my-service"

	t.Run("Returns token cached in netrc", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		sampleTokenContents := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
		initialContent := `
machine http://conjur/authn-oidc/my-service
	login [oidc]
	password ` + sampleTokenContents

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		token := readCachedAccessToken(config)
		assert.NotNil(t, token)
		assert.Equal(t, sampleTokenContents, string(token.Raw()))
	})

	t.Run("Returns empty token if saved token is invalid", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		initialContent := `
machine http://conjur/authn-oidc/my-service
	login [oidc]
	password token-contents`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		token := readCachedAccessToken(config)
		assert.Nil(t, token)
	})

	t.Run("Returns empty token if machine does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		token := readCachedAccessToken(config)
		assert.Nil(t, token)
	})
}

func setupConfig(t *testing.T) Config {
	tempDir := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	return Config{
		ApplianceURL: "http://conjur",
		NetRCPath:    filepath.Join(tempDir, ".netrc"),
	}
}
