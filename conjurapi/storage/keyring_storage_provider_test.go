package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/sirupsen/logrus"
	"github.com/zalando/go-keyring"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKeyringAvailable(t *testing.T) {
	// Set DBUS_SESSION_BUS_ADDRESS so the Secret-Service guard does not fire on
	// Linux/BSD CI runners. This test verifies mock behaviour; guard behaviour
	// is covered in TestIsKeyringAvailable_HeadlessLinux.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=/tmp/dbus-test-mock")

	// Mock that errors on every operation → IsKeyringAvailable must return false.
	keyring.MockInitWithError(errors.New("keyring unavailable"))
	assert.False(t, IsKeyringAvailable())

	// Healthy mock → IsKeyringAvailable must return true.
	keyring.MockInit()
	assert.True(t, IsKeyringAvailable())
}

func TestIsKeyringAvailable_HeadlessLinux(t *testing.T) {
	if !isSecretServicePlatform() {
		t.Skip("D-Bus guard only applies to Secret Service platforms (Linux and select BSDs)")
	}

	// Redirect the runtime-dir lookup to an empty temp dir so the socket
	// discovery path returns false regardless of the host environment.
	tmpDir := t.TempDir()
	origRuntimeDir := dbusUserRuntimeDir
	dbusUserRuntimeDir = func() string { return tmpDir }
	t.Cleanup(func() { dbusUserRuntimeDir = origRuntimeDir })

	// Install a healthy mock so that if the early return is absent, the
	// function would return true — making the assertions below real tests.
	keyring.MockInit()
	t.Cleanup(func() { keyring.MockInit() })

	// No env var, no socket file → autolaunch would be triggered → guard fires.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	assert.False(t, IsKeyringAvailable(),
		"expected false: no DBUS_SESSION_BUS_ADDRESS and no socket file present")

	// DBUS_SESSION_BUS_ADDRESS=autolaunch: is godbus's explicit "please launch"
	// sentinel — treat it the same as unset.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "autolaunch:")
	assert.False(t, IsKeyringAvailable(),
		"expected false: DBUS_SESSION_BUS_ADDRESS=autolaunch: must be treated as unset")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")

	// Socket at <runtimeDir>/bus (systemd socket-activation) → no autolaunch needed.
	busSocket := filepath.Join(tmpDir, "bus")
	f, err := os.Create(busSocket)
	require.NoError(t, err)
	f.Close()
	assert.True(t, IsKeyringAvailable(),
		"expected true: socket at runtimeDir/bus present (mirrors systemd /run/user/<uid>/bus)")
	require.NoError(t, os.Remove(busSocket))

	// Session file at <runtimeDir>/dbus-session (Ubuntu 16.04 style) → no autolaunch needed.
	sessionFile := filepath.Join(tmpDir, "dbus-session")
	f, err = os.Create(sessionFile)
	require.NoError(t, err)
	f.Close()
	assert.True(t, IsKeyringAvailable(),
		"expected true: dbus-session file at runtimeDir/dbus-session present (Ubuntu 16.04 style)")
	require.NoError(t, os.Remove(sessionFile))

	// DBUS_SESSION_BUS_ADDRESS set to a real address → guard must not fire.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	assert.True(t, IsKeyringAvailable(),
		"expected true: DBUS_SESSION_BUS_ADDRESS is set to a non-autolaunch address")
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

func TestKeyringStorageProvider_ErrorHandling(t *testing.T) {
	storage := setupTestStorageWithError(t, errors.New("test error"))

	testCases := []struct {
		name   string
		assert func(t *testing.T, logOutput *bytes.Buffer)
	}{
		{
			name: "StoreCredentials",
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				err := storage.StoreCredentials("test-login", "test-password")
				assertWriteError(t, logOutput, err)
			},
		},
		{
			name: "ReadCredentials",
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				_, _, err := storage.ReadCredentials()
				assertReadError(t, logOutput, err)
			},
		},
		{
			name: "StoreAuthnToken",
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				err := storage.StoreAuthnToken([]byte("test-authn-token"))
				assertWriteError(t, logOutput, err)
			},
		},
		{
			name: "ReadAuthnToken",
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				_, err := storage.ReadAuthnToken()
				assertReadError(t, logOutput, err)
			},
		},
		{
			name: "PurgeCredentials",
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				err := storage.PurgeCredentials()
				// We expect the error to be logged, but not returned
				assert.NoError(t, err)
				// There should be a log entry for each key that failed to be deleted
				assert.Contains(t, logOutput.String(), "Error when deleting login from keyring: test error")
				assert.Contains(t, logOutput.String(), "Error when deleting password from keyring: test error")
				assert.Contains(t, logOutput.String(), "Error when deleting authn_token from keyring: test error")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Intercept the log output
			var logOutput bytes.Buffer
			logging.ApiLog.SetOutput(&logOutput)
			// Set the log level to debug to capture all logs
			logging.ApiLog.SetLevel(logrus.DebugLevel)

			tc.assert(t, &logOutput)

			// Reset the log output
			t.Cleanup(func() {
				logging.ApiLog.SetOutput(os.Stdout)
				logging.ApiLog.SetLevel(logrus.InfoLevel)
			})
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

func setupTestStorageWithError(t *testing.T, err error) *KeyringStorageProvider {
	keyring.MockInitWithError(err)

	testMachineName := "conjur_api_go_test" + t.TempDir()
	return NewKeyringStorageProvider(testMachineName)
}

func assertWriteError(t *testing.T, logOutput *bytes.Buffer, err error) {
	// Check that the original error is logged but only the wrapped error is returned
	assert.ErrorIs(t, err, ErrWritingCredentials)
	assert.Contains(t, logOutput.String(), "test error")
}

func assertReadError(t *testing.T, logOutput *bytes.Buffer, err error) {
	// Check that the original error is logged but only the wrapped error is returned
	assert.ErrorIs(t, err, ErrReadingCredentials)
	assert.Contains(t, logOutput.String(), "test error")
}
