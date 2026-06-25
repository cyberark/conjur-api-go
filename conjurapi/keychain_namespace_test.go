package conjurapi

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// initMockKeyring installs an in-memory keyring for the test and restores an
// unavailable keyring provider afterward so other tests can assert default
// storage behavior when the OS keyring is absent.
func initMockKeyring(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	t.Cleanup(func() {
		keyring.MockInitWithError(errors.New("keyring unavailable for test isolation"))
	})
}

func TestLoadConfig_KeychainNamespace(t *testing.T) {
	t.Run("Given conjurrc sets keychain_namespace and env is unset, when LoadConfig runs, then YAML value is used", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		home := t.TempDir()
		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")

		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
keychain_namespace: tenant-a
`), 0600)
		require.NoError(t, err)

		config, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", config.KeychainNamespace)
	})

	t.Run("Given YAML and env both set, when LoadConfig runs, then env overrides YAML", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		home := t.TempDir()
		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
		t.Setenv(keychainNamespaceEnvVar, "tenant-b")

		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
keychain_namespace: tenant-a
`), 0600)
		require.NoError(t, err)

		config, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "tenant-b", config.KeychainNamespace)
	})

	t.Run("Given invalid namespace characters, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		cases := []struct {
			name  string
			value string
		}{
			{name: "slash", value: "tenant/a"},
			{name: "backslash", value: `tenant\a`},
			{name: "colon", value: "tenant:a"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := ClearEnv()
				defer e.RestoreEnv()

				home := t.TempDir()
				os.Setenv("HOME", home)
				os.Setenv("CONJUR_ACCOUNT", "account")
				os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
				t.Setenv(keychainNamespaceEnvVar, tc.value)

				_, err := LoadConfig()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid character")
			})
		}
	})

	t.Run("Given empty CONJUR_KEYCHAIN_NAMESPACE, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		home := t.TempDir()
		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
		t.Setenv(keychainNamespaceEnvVar, "")

		_, err := LoadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CONJUR_KEYCHAIN_NAMESPACE must not be empty")
	})

	t.Run("Given null byte in namespace, when validateKeychainNamespace runs, then an error is returned", func(t *testing.T) {
		err := validateKeychainNamespace("tenant\x00a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid character")
	})

	t.Run("Given empty keychain_namespace in conjurrc, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		home := t.TempDir()
		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")

		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
keychain_namespace: ""
`), 0600)
		require.NoError(t, err)

		_, err = LoadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keychain_namespace must not be empty")
	})

	t.Run("Given keychain_namespace key with no value in conjurrc, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		home := t.TempDir()
		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")

		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
keychain_namespace:
`), 0600)
		require.NoError(t, err)

		_, err = LoadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keychain_namespace must not be empty")
	})
}

func TestConfig_Validate_respectsExplicitKeychainNamespace(t *testing.T) {
	t.Setenv(keychainNamespaceEnvVar, "tenant-b")

	config := Config{
		ApplianceURL:      "https://conjur.example.com",
		Account:           "myorg",
		Environment:       EnvironmentSH,
		KeychainNamespace: "tenant-a",
	}
	require.NoError(t, config.Validate())
	assert.Equal(t, "tenant-a", config.KeychainNamespace)
}

func TestConfig_Validate_resolvesKeychainNamespaceFromEnv(t *testing.T) {
	t.Setenv(keychainNamespaceEnvVar, "tenant-b")

	config := Config{
		ApplianceURL: "https://conjur.example.com",
		Account:      "myorg",
		Environment:  EnvironmentSH,
	}
	require.NoError(t, config.Validate())
	assert.Equal(t, "tenant-b", config.KeychainNamespace)
}

func TestConfig_Validate_skipsKeychainNamespaceReResolutionAfterLoadConfig(t *testing.T) {
	e := ClearEnv()
	defer e.RestoreEnv()

	home := t.TempDir()
	os.Setenv("HOME", home)
	os.Setenv("CONJUR_ACCOUNT", "account")
	os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
	t.Setenv(keychainNamespaceEnvVar, "tenant-b")

	conjurrc := path.Join(home, ".conjurrc")
	err := os.WriteFile(conjurrc, []byte(`---
keychain_namespace: tenant-a
`), 0600)
	require.NoError(t, err)

	config, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "tenant-b", config.KeychainNamespace)

	config.KeychainNamespace = ""
	require.NoError(t, config.Validate())
	assert.Empty(t, config.KeychainNamespace)
}

func TestConfig_SetKeychainNamespaceResolved_skipsEnvOnHandBuiltConfig(t *testing.T) {
	t.Setenv(keychainNamespaceEnvVar, "tenant-b")

	config := Config{
		ApplianceURL:      "https://conjur.example.com",
		Account:           "myorg",
		Environment:       EnvironmentSH,
		KeychainNamespace: "tenant-a",
	}
	require.NoError(t, config.Validate())
	require.Equal(t, "tenant-a", config.KeychainNamespace)

	config.KeychainNamespace = ""
	config.SetKeychainNamespaceResolved(true)
	require.NoError(t, config.Validate())
	assert.Empty(t, config.KeychainNamespace)
}

func TestLoadConfig_KeychainNamespace_mergeKeyAndAnchor(t *testing.T) {
	e := ClearEnv()
	defer e.RestoreEnv()

	home := t.TempDir()
	os.Setenv("HOME", home)
	os.Setenv("CONJUR_ACCOUNT", "account")
	os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")

	t.Run("Given empty keychain_namespace via merge key, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
defaults: &defaults
  keychain_namespace: ""
<<: *defaults
`), 0600)
		require.NoError(t, err)

		_, err = LoadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keychain_namespace must not be empty")
	})

	t.Run("Given empty keychain_namespace via anchor, when LoadConfig runs, then an error is returned", func(t *testing.T) {
		conjurrc := path.Join(home, ".conjurrc")
		err := os.WriteFile(conjurrc, []byte(`---
empty: &empty ""
keychain_namespace: *empty
`), 0600)
		require.NoError(t, err)

		_, err = LoadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keychain_namespace must not be empty")
	})
}

func TestKeyringServiceName(t *testing.T) {
	baseConfig := Config{
		ApplianceURL: "https://conjur.example.com",
	}

	t.Run("Given namespace unset, when keyringServiceName runs, then machine name has no suffix", func(t *testing.T) {
		assert.Equal(t, "https://conjur.example.com/authn", keyringServiceName(baseConfig))
	})

	t.Run("Given namespace set, when keyringServiceName runs, then service name is machineName:namespace", func(t *testing.T) {
		config := baseConfig
		config.KeychainNamespace = "tenant-a"
		assert.Equal(t, "https://conjur.example.com/authn:tenant-a", keyringServiceName(config))
	})
}

func TestCreateStorageProvider_KeychainNamespace(t *testing.T) {
	initMockKeyring(t)

	t.Run("Given namespace set and keyring storage, when createStorageProvider runs, then namespaced service name is used", func(t *testing.T) {
		config := Config{
			ApplianceURL:      "https://conjur.example.com",
			CredentialStorage: CredentialStorageKeyring,
			KeychainNamespace: "tenant-a",
		}

		provider, err := createStorageProvider(config)
		require.NoError(t, err)
		require.IsType(t, &storage.KeyringStorageProvider{}, provider)

		err = provider.StoreCredentials("login", "password")
		require.NoError(t, err)

		serviceName := keyringServiceName(config)
		login, err := keyring.Get(serviceName, "login")
		require.NoError(t, err)
		assert.Equal(t, "login", login)
	})

	t.Run("Given namespace unset and keyring storage, when createStorageProvider runs, then machine name only is used", func(t *testing.T) {
		config := Config{
			ApplianceURL:      "https://conjur.example.com",
			CredentialStorage: CredentialStorageKeyring,
		}

		provider, err := createStorageProvider(config)
		require.NoError(t, err)
		require.IsType(t, &storage.KeyringStorageProvider{}, provider)

		err = provider.StoreCredentials("login", "password")
		require.NoError(t, err)

		login, err := keyring.Get(getMachineName(config), "login")
		require.NoError(t, err)
		assert.Equal(t, "login", login)
	})
}

func TestNewClientFromEnvironment_KeychainNamespace(t *testing.T) {
	initMockKeyring(t)

	e := ClearEnv()
	defer e.RestoreEnv()

	home := t.TempDir()
	os.Setenv("HOME", home)
	os.Setenv("CONJUR_ACCOUNT", "account")
	os.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
	os.Setenv("CONJUR_CREDENTIAL_STORAGE", "keyring")
	t.Setenv(keychainNamespaceEnvVar, "tenant-a")
	os.Setenv("CONJUR_AUTHN_LOGIN", "user")
	os.Setenv("CONJUR_AUTHN_API_KEY", "password")

	config, err := LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", config.KeychainNamespace)

	client, err := NewClientFromEnvironment(config)
	require.NoError(t, err)
	require.NotNil(t, client)

	provider, err := createStorageProvider(config)
	require.NoError(t, err)
	err = provider.StoreCredentials("login", "password")
	require.NoError(t, err)

	login, err := keyring.Get(keyringServiceName(config), "login")
	require.NoError(t, err)
	assert.Equal(t, "login", login)
}

func TestKeychainNamespace_Isolation(t *testing.T) {
	initMockKeyring(t)

	base := Config{
		ApplianceURL:      "https://conjur.example.com",
		CredentialStorage: CredentialStorageKeyring,
	}

	configA := base
	configA.KeychainNamespace = "tenant-a"
	providerA, err := createStorageProvider(configA)
	require.NoError(t, err)
	err = providerA.StoreCredentials("login-a", "password-a")
	require.NoError(t, err)

	configB := base
	configB.KeychainNamespace = "tenant-b"
	providerB, err := createStorageProvider(configB)
	require.NoError(t, err)
	err = providerB.StoreCredentials("login-b", "password-b")
	require.NoError(t, err)

	loginA, passwordA, err := providerA.ReadCredentials()
	require.NoError(t, err)
	assert.Equal(t, "login-a", loginA)
	assert.Equal(t, "password-a", passwordA)

	loginB, passwordB, err := providerB.ReadCredentials()
	require.NoError(t, err)
	assert.Equal(t, "login-b", loginB)
	assert.Equal(t, "password-b", passwordB)

	loginOnA, err := keyring.Get(keyringServiceName(configA), "login")
	require.NoError(t, err)
	assert.Equal(t, "login-a", loginOnA)

	loginOnB, err := keyring.Get(keyringServiceName(configB), "login")
	require.NoError(t, err)
	assert.Equal(t, "login-b", loginOnB)

	_, err = keyring.Get(keyringServiceName(configA), "password")
	require.NoError(t, err)
	_, err = keyring.Get(keyringServiceName(configB), "password")
	require.NoError(t, err)
}
