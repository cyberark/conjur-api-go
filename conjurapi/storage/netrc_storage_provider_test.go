package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

type netrcTestConfig struct {
	ApplianceURL string
	NetRCPath    string
	AuthnType    string
	ServiceID    string
}

func TestStoreCredentials(t *testing.T) {
	config := setupConfig(t)

	t.Run("Creates file if it does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		storage := setupStorage(config)
		err := storage.StoreCredentials("login", "apiKey")
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

		storage := setupStorage(config)
		err = storage.StoreCredentials("login", "apiKey")
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

		storage := setupStorage(config)
		err = storage.StoreCredentials("login", "apiKey")
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL)
		assert.Contains(t, string(contents), "apiKey")
	})
}

func TestReadCredentials(t *testing.T) {
	config := setupConfig(t)

	t.Run("Returns credentials from netrc", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		initialContent := `
machine http://conjur/authn
	login admin
	password password`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		storage := setupStorage(config)
		login, apiKey, err := storage.ReadCredentials()
		assert.NoError(t, err)
		assert.Equal(t, "admin", login)
		assert.Equal(t, "password", apiKey)
	})

	t.Run("Returns error if file does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		storage := setupStorage(config)
		login, apiKey, err := storage.ReadCredentials()
		assert.Error(t, err)
		assert.Equal(t, "", login)
		assert.Equal(t, "", apiKey)
	})

	t.Run("Returns error if machine does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)
		_, err := os.Create(config.NetRCPath)
		assert.NoError(t, err)

		storage := setupStorage(config)
		login, apiKey, err := storage.ReadCredentials()
		assert.Error(t, err)
		assert.Equal(t, "", login)
		assert.Equal(t, "", apiKey)
	})
}

func TestStoreAuthnToken(t *testing.T) {
	config := setupConfig(t)
	t.Run("Uses authn type in machine url", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		oidcConfig := netrcTestConfig{
			ApplianceURL: config.ApplianceURL,
			NetRCPath:    config.NetRCPath,
			AuthnType:    "oidc",
			ServiceID:    "my-service",
		}

		storage := setupStorage(oidcConfig)
		err := storage.StoreAuthnToken([]byte("token-contents"))
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.Contains(t, string(contents), config.ApplianceURL+"/authn-oidc/my-service")
		assert.Contains(t, string(contents), "token-contents")
	})
}

func TestReadAuthnToken(t *testing.T) {
	config := setupConfig(t)
	config.AuthnType = "oidc"
	config.ServiceID = "my-service"

	t.Run("Returns token cached in netrc", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		initialContent := `
machine http://conjur/authn-oidc/my-service
	login [oidc]
	password token-contents`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		storage := setupStorage(config)
		token, err := storage.ReadAuthnToken()
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, "token-contents", string(token))
	})

	t.Run("Returns empty token if file does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		storage := setupStorage(config)
		token, _ := storage.ReadAuthnToken()
		assert.Nil(t, token)
	})
}

func TestPurgeCredentials(t *testing.T) {
	config := setupConfig(t)

	t.Run("Removes credentials from netrc", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		initialContent := `
machine http://conjur/authn
	login admin
	password password`

		err := os.WriteFile(config.NetRCPath, []byte(initialContent), 0600)
		assert.NoError(t, err)

		storage := setupStorage(config)
		err = storage.PurgeCredentials()
		assert.NoError(t, err)

		contents, err := os.ReadFile(config.NetRCPath)
		assert.NoError(t, err)
		assert.NotContains(t, string(contents), config.ApplianceURL)
		assert.NotContains(t, string(contents), "password")
	})

	t.Run("Does not error if file does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)

		storage := setupStorage(config)
		err := storage.PurgeCredentials()
		assert.NoError(t, err)
	})

	t.Run("Does not error if machine does not exist", func(t *testing.T) {
		os.Remove(config.NetRCPath)
		_, err := os.Create(config.NetRCPath)
		assert.NoError(t, err)

		storage := setupStorage(config)
		err = storage.PurgeCredentials()
		assert.NoError(t, err)
	})
}

func setupConfig(t *testing.T) netrcTestConfig {
	tempDir := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	return netrcTestConfig{
		ApplianceURL: "http://conjur",
		NetRCPath:    filepath.Join(tempDir, ".netrc"),
	}
}

func setupStorage(config netrcTestConfig) *NetrcStorageProvider {
	return NewNetrcStorageProvider(
		config.NetRCPath,
		config.ApplianceURL,
		config.AuthnType,
		config.ServiceID,
	)
}
