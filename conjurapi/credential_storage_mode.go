// Package conjurapi implements the Conjur API client.
package conjurapi

import (
	"os"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// CredentialStorageMode controls whether credential storage backends accept writes.
type CredentialStorageMode string

const (
	// CredentialStorageModeReadWrite allows reading and writing cached credentials.
	CredentialStorageModeReadWrite CredentialStorageMode = "readwrite"
	// CredentialStorageModeReadOnly allows reading cached credentials but suppresses writes.
	CredentialStorageModeReadOnly CredentialStorageMode = "readonly"
)

const credentialStorageModeEnvVar = "CONJUR_CREDENTIAL_STORAGE_MODE"

var (
	callerDefaultCredentialStorageMode     CredentialStorageMode
	callerDefaultCredentialStorageModeSet  bool
)

// WithDefaultCredentialStorageMode sets the package-level default used when
// CONJUR_CREDENTIAL_STORAGE_MODE is unset. It does not override an explicit env value.
// Only CredentialStorageModeReadWrite and CredentialStorageModeReadOnly are accepted;
// other values are logged and ignored. Call from main or init before LoadConfig or
// NewClient so env resolution sees the intended default (summon B.2 sets ReadOnly once
// per process). Not safe for concurrent use from multiple goroutines.
func WithDefaultCredentialStorageMode(mode CredentialStorageMode) {
	parsed, valid := parseCredentialStorageMode(string(mode))
	if !valid {
		logging.ApiLog.Warnf(
			"Invalid credential storage mode %q, ignoring WithDefaultCredentialStorageMode",
			mode,
		)
		return
	}

	callerDefaultCredentialStorageMode = parsed
	callerDefaultCredentialStorageModeSet = true
}

func parseCredentialStorageMode(raw string) (CredentialStorageMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(CredentialStorageModeReadWrite):
		return CredentialStorageModeReadWrite, true
	case string(CredentialStorageModeReadOnly):
		return CredentialStorageModeReadOnly, true
	default:
		return "", false
	}
}

func effectiveDefaultCredentialStorageMode() CredentialStorageMode {
	if callerDefaultCredentialStorageModeSet {
		return callerDefaultCredentialStorageMode
	}
	return CredentialStorageModeReadWrite
}

func mergeCredentialStorageMode(existing, incoming CredentialStorageMode) CredentialStorageMode {
	if mode, valid := parseCredentialStorageMode(string(existing)); valid {
		return mode
	}
	if mode, valid := parseCredentialStorageMode(string(incoming)); valid {
		return mode
	}
	return ""
}

func resolveCredentialStorageMode(c *Config) {
	if mode, valid := parseCredentialStorageMode(string(c.CredentialStorageMode)); valid {
		c.CredentialStorageMode = mode
		return
	}

	raw, ok := os.LookupEnv(credentialStorageModeEnvVar)
	if !ok || raw == "" {
		c.CredentialStorageMode = effectiveDefaultCredentialStorageMode()
		return
	}

	mode, valid := parseCredentialStorageMode(raw)
	if valid {
		c.CredentialStorageMode = mode
		return
	}

	fallback := effectiveDefaultCredentialStorageMode()
	logging.ApiLog.Warnf(
		"Invalid %s value %q, using %s",
		credentialStorageModeEnvVar,
		raw,
		fallback,
	)
	c.CredentialStorageMode = fallback
}
