package conjurapi

import (
	"errors"
	"fmt"
	"os"

	"github.com/bgentry/go-netrc/netrc"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

// getMachineName returns the machine name to use in the .netrc file. It contains the appliance URL
// and the path to the authentication endpoint.
func getMachineName(config Config) string {
	if config.AuthnType != "" && config.AuthnType != "authn" {
		authnType := fmt.Sprintf("authn-%s", config.AuthnType)
		return fmt.Sprintf("%s/%s/%s", config.ApplianceURL, authnType, config.ServiceID)
	}

	return config.ApplianceURL + "/authn"
}

// storeCredentials stores credentials to the specified .netrc file
func storeCredentials(config Config, login string, apiKey string) error {
	machineName := getMachineName(config)
	filePath := config.NetRCPath

	_, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = os.WriteFile(filePath, []byte{}, 0600)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	nrc, err := netrc.ParseFile(filePath)
	if err != nil {
		return err
	}

	m := nrc.FindMachine(machineName)
	if m == nil || m.IsDefault() {
		_ = nrc.NewMachine(machineName, login, apiKey, "")
	} else {
		m.UpdateLogin(login)
		m.UpdatePassword(apiKey)
	}

	data, err := nrc.MarshalText()
	if err != nil {
		return err
	}

	if data[len(data)-1] != byte('\n') {
		data = append(data, byte('\n'))
	}

	return os.WriteFile(filePath, data, 0600)
}

// Fetches the cached conjur access token. We only do this for OIDC since we don't have access
// to the Conjur API key and this is the only credential we can save.
func readCachedAccessToken(config Config) *authn.AuthnToken {
	if nrc, err := LoginPairFromNetRC(config); err == nil {
		token, err := authn.NewToken([]byte(nrc.APIKey))
		if err == nil {
			token.FromJSON(token.Raw())
			return token
		}
	}
	return nil
}

// purgeCredentials purges credentials from the specified .netrc file
func purgeCredentials(config Config) error {
	// Remove cached credentials (username, api key) from .netrc
	machineName := getMachineName(config)
	filePath := config.NetRCPath

	nrc, err := netrc.ParseFile(filePath)
	if err != nil {
		// If the .netrc file doesn't exist, we don't need to do anything
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		// Any other error should be returned
		return err
	}

	nrc.RemoveMachine(machineName)

	data, err := nrc.MarshalText()
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0600)
}
