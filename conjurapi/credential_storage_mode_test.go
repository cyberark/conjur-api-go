package conjurapi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetDefaultCredentialStorageModeForTests() {
	callerDefaultCredentialStorageMode = ""
	callerDefaultCredentialStorageModeSet = false
}

func TestMain(m *testing.M) {
	resetDefaultCredentialStorageModeForTests()
	os.Exit(m.Run())
}

func TestCredentialStorageModeConstants(t *testing.T) {
	assert.Equal(t, CredentialStorageMode("readwrite"), CredentialStorageModeReadWrite)
	assert.Equal(t, CredentialStorageMode("readonly"), CredentialStorageModeReadOnly)
}

func TestResolveCredentialStorageMode(t *testing.T) {
	t.Run("defaults to ReadWrite when unset", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)
		t.Setenv(credentialStorageModeEnvVar, "")

		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadWrite, config.CredentialStorageMode)
	})

	t.Run("reads env case-insensitively", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)

		for _, raw := range []string{"readonly", "ReadOnly", "READONLY"} {
			t.Run(raw, func(t *testing.T) {
				t.Setenv(credentialStorageModeEnvVar, raw)
				config := &Config{}
				resolveCredentialStorageMode(config)
				assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
			})
		}
	})

	t.Run("uses caller default when env unset", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)
		t.Setenv(credentialStorageModeEnvVar, "")

		WithDefaultCredentialStorageMode(CredentialStorageModeReadOnly)
		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
	})

	t.Run("ignores invalid caller default", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)
		t.Setenv(credentialStorageModeEnvVar, "")

		WithDefaultCredentialStorageMode(CredentialStorageMode("readnly"))
		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadWrite, config.CredentialStorageMode)
	})

	t.Run("env overrides caller default", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)

		WithDefaultCredentialStorageMode(CredentialStorageModeReadOnly)
		t.Setenv(credentialStorageModeEnvVar, "readwrite")

		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadWrite, config.CredentialStorageMode)
	})

	t.Run("invalid env falls back to caller default", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)

		WithDefaultCredentialStorageMode(CredentialStorageModeReadOnly)
		t.Setenv(credentialStorageModeEnvVar, "invalid-mode")

		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
	})

	t.Run("invalid env falls back to ReadWrite when no caller default", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)
		t.Setenv(credentialStorageModeEnvVar, "invalid-mode")

		config := &Config{}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadWrite, config.CredentialStorageMode)
	})

	t.Run("explicit config beats env and caller default", func(t *testing.T) {
		t.Cleanup(resetDefaultCredentialStorageModeForTests)

		WithDefaultCredentialStorageMode(CredentialStorageModeReadWrite)
		t.Setenv(credentialStorageModeEnvVar, "readwrite")

		config := &Config{CredentialStorageMode: CredentialStorageModeReadOnly}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
	})

	t.Run("normalizes explicit config case", func(t *testing.T) {
		config := &Config{CredentialStorageMode: CredentialStorageMode("ReadOnly")}
		resolveCredentialStorageMode(config)
		assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
	})
}

func TestConfig_Validate_resolvesCredentialStorageMode(t *testing.T) {
	t.Cleanup(resetDefaultCredentialStorageModeForTests)
	t.Setenv(credentialStorageModeEnvVar, "readonly")

	config := Config{
		ApplianceURL: "https://conjur.example.com",
		Account:      "myorg",
		Environment:  EnvironmentSH,
	}
	require.NoError(t, config.Validate())
	assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
}

func TestConfig_Validate_respectsExplicitCredentialStorageMode(t *testing.T) {
	t.Cleanup(resetDefaultCredentialStorageModeForTests)
	t.Setenv(credentialStorageModeEnvVar, "readwrite")

	config := Config{
		ApplianceURL:          "https://conjur.example.com",
		Account:               "myorg",
		Environment:           EnvironmentSH,
		CredentialStorageMode: CredentialStorageModeReadOnly,
	}
	require.NoError(t, config.Validate())
	assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
}

func TestLoadConfig_resolvesCredentialStorageMode(t *testing.T) {
	t.Cleanup(resetDefaultCredentialStorageModeForTests)

	t.Setenv("CONJUR_APPLIANCE_URL", "https://conjur.example.com")
	t.Setenv("CONJUR_ACCOUNT", "myorg")
	t.Setenv("CONJUR_ENVIRONMENT", "self-hosted")
	t.Setenv(credentialStorageModeEnvVar, "readonly")

	config, err := LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, CredentialStorageModeReadOnly, config.CredentialStorageMode)
}
