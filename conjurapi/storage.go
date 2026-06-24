package conjurapi

import (
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/cyberark/conjur-api-go/conjurapi/storage"
)

const (
	CredentialStorageFile    = "file"
	CredentialStorageKeyring = "keyring"
	CredentialStorageNone    = "none"
)

func createStorageProvider(config Config) (CredentialStorageProvider, error) {
	if config.CredentialStorage == "" {
		config.CredentialStorage = getDefaultCredentialStorage()
		logging.ApiLog.Debugf("No credential storage specified, defaulting to %s", config.CredentialStorage)
	}

	switch config.CredentialStorage {
	case CredentialStorageFile:
		provider, err := storage.NewNetrcStorageProvider(
			config.NetRCPath,
			getMachineName(config),
		)
		if err != nil {
			return nil, err
		}
		return provider, nil
	case CredentialStorageKeyring:
		if !storage.IsKeyringAvailable() {
			return nil, fmt.Errorf("Keyring is not available")
		}

		return storage.NewKeyringStorageProvider(
			keyringServiceName(config),
		), nil
	case CredentialStorageNone:
		// Don't store credentials
		logging.ApiLog.Debugf("Not storing credentials")
		return nil, nil
	default:
		return nil, fmt.Errorf("Unknown credential storage type")
	}
}

// keyringServiceName returns the OS keyring service name for the config.
// When KeychainNamespace is set, the name is machineName:namespace; otherwise
// it matches getMachineName.
func keyringServiceName(config Config) string {
	machineName := getMachineName(config)
	if config.KeychainNamespace == "" {
		return machineName
	}
	return fmt.Sprintf("%s:%s", machineName, config.KeychainNamespace)
}

// getMachineName returns the machine name to use in the .netrc file or other credential storage.
// It contains the appliance URL and the path to the authentication endpoint.
func getMachineName(config Config) string {
	if config.AuthnType != "" && config.AuthnType != "authn" {
		authnType := fmt.Sprintf("authn-%s", config.AuthnType)
		return fmt.Sprintf("%s/%s/%s", config.ApplianceURL, authnType, config.ServiceID)
	}

	return config.ApplianceURL + "/authn"
}

func getDefaultCredentialStorage() string {
	if storage.IsKeyringAvailable() {
		return CredentialStorageKeyring
	}

	return CredentialStorageFile
}
