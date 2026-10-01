package storage

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/zalando/go-keyring"
)

type KeyringStorageProvider struct {
	machineName string
}

var keyring_keys = []string{"login", "password", "authn_token"}
var ErrWritingCredentials = errors.New("unable to write credentials to keyring")
var ErrReadingCredentials = errors.New("unable to read credentials from keyring")

func NewKeyringStorageProvider(machineName string) *KeyringStorageProvider {
	return &KeyringStorageProvider{
		machineName: machineName,
	}
}

// dbusUserRuntimeDir returns the per-user D-Bus runtime directory
// (/run/user/<uid>). It is a variable so tests can redirect it to a temp dir.
var dbusUserRuntimeDir = func() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join("/run/user", u.Uid)
}

// isSecretServicePlatform reports whether the current platform uses
// go-keyring's Secret Service backend (which talks to D-Bus). This mirrors
// the build tag on go-keyring's keyring_unix.go:
//
//	(dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd
//
// FreeBSD and DragonFly without cgo fall back to go-keyring's
// fallbackServiceProvider (returns ErrUnsupportedPlatform), so the D-Bus guard
// is a no-op there — but it is harmless and makes the intent explicit.
func isSecretServicePlatform() bool {
	switch runtime.GOOS {
	case "linux", "freebsd", "dragonfly", "netbsd", "openbsd":
		return true
	}
	return false
}

// IsKeyringAvailable returns true if the keyring is available on the system.
// On platforms that use the Secret Service backend (Linux and select BSDs),
// if no D-Bus session is reachable without autolaunching a daemon, return
// false immediately to prevent go-keyring from calling dbus.SessionBus() —
// which autolaunches dbus-daemon as an orphan process in headless environments.
func IsKeyringAvailable() bool {
	if isSecretServicePlatform() && !dbusSessionAvailable() {
		logging.ApiLog.Debug(
			"no D-Bus session available — skipping keyring, falling back to file storage",
		)
		return false
	}
	// Try to get a value. If there's an error other than "not found", then the
	// keyring is not available.
	_, err := keyring.Get("test", "test")
	return err == keyring.ErrNotFound
}

// dbusSessionAvailable reports whether a D-Bus session bus is reachable
// without autolaunching a new daemon. It mirrors the discovery logic in
// github.com/godbus/dbus/v5 getSessionBusAddress:
//
//  1. DBUS_SESSION_BUS_ADDRESS set to a real address → available.
//  2. Socket at /run/user/<uid>/bus (systemd socket-activation) → available.
//  3. Session file at /run/user/<uid>/dbus-session → available.
//  4. None of the above → go-keyring would trigger dbus-daemon autolaunch.
func dbusSessionAvailable() bool {
	if addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" && addr != "autolaunch:" {
		return true
	}
	runDir := dbusUserRuntimeDir()
	if runDir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(runDir, "bus")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(runDir, "dbus-session")); err == nil {
		return true
	}
	return false
}

func (k *KeyringStorageProvider) StoreCredentials(login string, password string) error {
	err := keyring.Set(k.machineName, "login", login)
	if err != nil {
		logging.ApiLog.Debug(err)
		return ErrWritingCredentials
	}

	err = keyring.Set(k.machineName, "password", password)
	if err != nil {
		logging.ApiLog.Debug(err)
		return ErrWritingCredentials
	}

	return nil
}

func (k *KeyringStorageProvider) ReadCredentials() (string, string, error) {
	login, err := keyring.Get(k.machineName, "login")
	if err != nil && err != keyring.ErrNotFound {
		logging.ApiLog.Debug(err)
		return "", "", ErrReadingCredentials
	}
	password, err := keyring.Get(k.machineName, "password")
	if err != nil && err != keyring.ErrNotFound {
		logging.ApiLog.Debug(err)
		return "", "", ErrReadingCredentials
	}
	return login, password, nil
}

func (k *KeyringStorageProvider) ReadAuthnToken() ([]byte, error) {
	token, err := keyring.Get(k.machineName, "authn_token")
	if err != nil && err != keyring.ErrNotFound {
		logging.ApiLog.Debug(err)
		return nil, ErrReadingCredentials
	}
	return []byte(token), nil
}

func (k *KeyringStorageProvider) StoreAuthnToken(token []byte) error {
	err := keyring.Set(k.machineName, "authn_token", string(token))
	if err != nil {
		logging.ApiLog.Debug(err)
		return ErrWritingCredentials
	}
	return nil
}

func (k *KeyringStorageProvider) PurgeCredentials() error {
	for _, key := range keyring_keys {
		err := keyring.Delete(k.machineName, key)
		if err != nil {
			logging.ApiLog.Debugf("Error when deleting %s from keyring: %s", key, err)
		}
	}
	return nil
}
