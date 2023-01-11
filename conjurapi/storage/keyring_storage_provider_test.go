package storage

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/stretchr/testify/assert"
)

func TestIsKeyringAvailable(t *testing.T) {
	// Keyring shouldn't be avaialble by default in the container running the tests
	// until we enable the mock keyring
	assert.False(t, IsKeyringAvailable())
	keyring.MockInit()
	assert.True(t, IsKeyringAvailable())
}

func TestKeyringStorageProvider_StoreCredentials(t *testing.T) {
	testCases := []struct {
		name              string
		expectedKeyValues map[string]string
	}{
		{
			name: "Stores credentials in keyring",
			expectedKeyValues: map[string]string{
				"login":       "test-login",
				"password":    "test-password",
				"authn_token": "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := setupTestStorage(t)

			err := storage.StoreCredentials(tc.expectedKeyValues["login"], tc.expectedKeyValues["password"])
			assert.NoError(t, err)

			for key, value := range tc.expectedKeyValues {
				item, err := keyring.Get(storage.machineName, key)

				// If the expected value is empty, we expect the key to not be found
				if value == "" {
					assert.Error(t, err)
					assert.ErrorIs(t, err, keyring.ErrNotFound)
					continue
				}

				// Otherwise, we expect the key to be found and the value to match
				assert.NoError(t, err)
				assert.Equal(t, value, string(item))
			}
		})
	}
}

func TestKeyringStorageProvider_ReadCredentials(t *testing.T) {
	testCases := []struct {
		name              string
		expectedKeyValues map[string]string
	}{
		{
			name: "Stores credentials in keyring",
			expectedKeyValues: map[string]string{
				"login":    "test-login",
				"password": "test-password",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := setupTestStorage(t)

			for key, value := range tc.expectedKeyValues {
				keyring.Set(storage.machineName, key, value)
			}

			u, p, err := storage.ReadCredentials()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedKeyValues["login"], u)
			assert.Equal(t, tc.expectedKeyValues["password"], p)
		})
	}
}

func TestKeyringStorageProvider_StoreAuthToken(t *testing.T) {
	testCases := []struct {
		name              string
		expectedKeyValues map[string]string
	}{
		{
			name: "Stores authn token in keyring",
			expectedKeyValues: map[string]string{
				"login":       "",
				"password":    "",
				"authn_token": "test-authn-token",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := setupTestStorage(t)

			err := storage.StoreAuthnToken([]byte(tc.expectedKeyValues["authn_token"]))
			assert.NoError(t, err)

			for key, value := range tc.expectedKeyValues {
				item, err := keyring.Get(storage.machineName, key)

				// If the expected value is empty, we expect the key to not be found
				if value == "" {
					assert.Error(t, err)
					assert.ErrorIs(t, err, keyring.ErrNotFound)
					continue
				}

				// Otherwise, we expect the key to be found and the value to match
				assert.NoError(t, err)
				assert.Equal(t, value, string(item))
			}
		})
	}
}

func TestKeyringStorageProvider_ReadAuthToken(t *testing.T) {
	testCases := []struct {
		name              string
		expectedKeyValues map[string]string
	}{
		{
			name: "Stores authn token in keyring",
			expectedKeyValues: map[string]string{
				"authn_token": "test-authn-token",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := setupTestStorage(t)

			for key, value := range tc.expectedKeyValues {
				keyring.Set(storage.machineName, key, value)
			}

			token, err := storage.ReadAuthnToken()
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedKeyValues["authn_token"], string(token))
		})
	}
}

func TestKeyringStorageProvider_PurgeCredentials(t *testing.T) {
	testCases := []struct {
		name              string
		expectedKeyValues map[string]string
	}{
		{
			name: "Purges credentials from keyring",
			expectedKeyValues: map[string]string{
				"login":       "test-login",
				"password":    "test-password",
				"authn_token": "test-authn-token",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := setupTestStorage(t)

			for key, value := range tc.expectedKeyValues {
				keyring.Set(storage.machineName, key, value)
			}

			err := storage.PurgeCredentials()
			assert.NoError(t, err)

			for key := range tc.expectedKeyValues {
				_, err := keyring.Get(storage.machineName, key)
				assert.Error(t, err)
				assert.ErrorIs(t, err, keyring.ErrNotFound)
			}
		})
	}
}

func setupTestStorage(t *testing.T) *KeyringStorageProvider {
	// Use a mock, in-memory provider for testing
	keyring.MockInit()

	testMachineName := "conjur_api_go_test" + t.TempDir()
	storage := NewKeyringStorageProvider(testMachineName)

	t.Cleanup(func() {
		for _, key := range keyring_keys {
			keyring.Delete(testMachineName, key)
		}
	})

	return storage
}
