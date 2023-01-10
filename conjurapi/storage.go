package conjurapi

import (
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/cyberark/conjur-api-go/conjurapi/storage"
)

func createStorageProvider(config Config) (CredentialStorageProvider, error) {
	if config.CredentialStorage == "" || config.CredentialStorage == "file" {
		return storage.NewNetrcStorageProvider(
			config.NetRCPath,
			config.ApplianceURL,
			config.AuthnType,
			config.ServiceID,
		), nil
	} else if config.CredentialStorage == "keyring" {
		//TODO: Add support for keyring
		return nil, fmt.Errorf("Keyring is not supported yet")
	} else if config.CredentialStorage == "none" {
		// Don't store credentials
		logging.ApiLog.Debugf("Not storing credentials")
		return nil, nil
	} else {
		return nil, fmt.Errorf("Unknown credential storage type")
	}
}
