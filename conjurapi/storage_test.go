package conjurapi

import (
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/storage"
	"github.com/stretchr/testify/assert"
	"github.com/zalando/go-keyring"
)

func TestGetMachineName(t *testing.T) {
	testCases := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "default authn",
			config: Config{
				ApplianceURL: "https://conjur",
			},
			expected: "https://conjur/authn",
		},
		{
			name: "authn-oidc",
			config: Config{
				ApplianceURL: "https://conjur",
				AuthnType:    "oidc",
				ServiceID:    "test-service",
			},
			expected: "https://conjur/authn-oidc/test-service",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			machineName := getMachineName(tc.config)
			assert.Equal(t, tc.expected, machineName)
		})
	}
}

func TestCreateStorageProvider(t *testing.T) {
	testCases := []struct {
		name   string
		config Config
		action func()
		assert func(t *testing.T, storageProvider CredentialStorageProvider, err error)
	}{
		{
			name: "default storage",
			config: Config{
				ApplianceURL: "https://conjur",
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				// Keyring shouldn't be avaialble by default in the container running the tests
				// Therefore it should default to netrc file storage
				assert.Nil(t, err)
				assert.NotNil(t, storageProvider)
				assert.IsType(t, &storage.NetrcStorageProvider{}, storageProvider)
			},
		},
		{
			name: "keyring storage when not available",
			config: Config{
				ApplianceURL:      "https://conjur",
				CredentialStorage: "keyring",
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.ErrorContains(t, err, "Keyring is not available")
			},
		},
		{
			name: "default storage with keyring available",
			config: Config{
				ApplianceURL: "https://conjur",
			},
			action: func() {
				// Enable a mock memory-based keyring storage
				keyring.MockInit()
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.Nil(t, err)
				assert.NotNil(t, storageProvider)
				assert.IsType(t, &storage.KeyringStorageProvider{}, storageProvider)
			},
		},
		{
			name: "keyring storage when available",
			config: Config{
				ApplianceURL:      "https://conjur",
				CredentialStorage: "keyring",
			},
			action: func() {
				// Enable a mock memory-based keyring storage
				keyring.MockInit()
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.Nil(t, err)
				assert.NotNil(t, storageProvider)
				assert.IsType(t, &storage.KeyringStorageProvider{}, storageProvider)
			},
		},
		{
			name: "netrc storage",
			config: Config{
				ApplianceURL:      "https://conjur",
				CredentialStorage: "file",
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.Nil(t, err)
				assert.NotNil(t, storageProvider)
				assert.IsType(t, &storage.NetrcStorageProvider{}, storageProvider)
			},
		},
		{
			name: "no storage",
			config: Config{
				ApplianceURL:      "https://conjur",
				CredentialStorage: "none",
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.Nil(t, err)
				assert.Nil(t, storageProvider)
			},
		},
		{
			name: "invalid storage option",
			config: Config{
				ApplianceURL:      "https://conjur",
				CredentialStorage: "invalid",
			},
			assert: func(t *testing.T, storageProvider CredentialStorageProvider, err error) {
				assert.ErrorContains(t, err, "Unknown credential storage type")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.action != nil {
				tc.action()
			}

			storage, err := createStorageProvider(tc.config)
			tc.assert(t, storage, err)
		})
	}
}
