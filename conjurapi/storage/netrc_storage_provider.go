package storage

import (
	"errors"
	"fmt"
	"os"

	"github.com/bgentry/go-netrc/netrc"
)

type NetrcStorageProvider struct {
	netRCPath    string
	applianceURL string
	authnType    string
	serviceID    string
}

func NewNetrcStorageProvider(netRCPath, applianceURL, authnType, serviceID string) *NetrcStorageProvider {
	return &NetrcStorageProvider{
		netRCPath:    netRCPath,
		applianceURL: applianceURL,
		authnType:    authnType,
		serviceID:    serviceID,
	}
}

// getMachineName returns the machine name to use in the .netrc file. It contains the appliance URL
// and the path to the authentication endpoint.
func (s *NetrcStorageProvider) getMachineName() string {
	if s.authnType != "" && s.authnType != "authn" {
		authnType := fmt.Sprintf("authn-%s", s.authnType)
		return fmt.Sprintf("%s/%s/%s", s.applianceURL, authnType, s.serviceID)
	}

	return s.applianceURL + "/authn"
}

// StoreCredentials stores credentials to the specified .netrc file
func (s *NetrcStorageProvider) StoreCredentials(login string, password string) error {
	machineName := s.getMachineName()
	filePath := s.netRCPath

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
		_ = nrc.NewMachine(machineName, login, password, "")
	} else {
		m.UpdateLogin(login)
		m.UpdatePassword(password)
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

func (s *NetrcStorageProvider) ReadCredentials() (string, string, error) {
	machineName := s.getMachineName()
	filePath := s.netRCPath

	nrc, err := netrc.ParseFile(filePath)
	if err != nil {
		return "", "", err
	}

	m := nrc.FindMachine(machineName)
	if m == nil {
		return "", "", fmt.Errorf("No credentials found in NetRCPath")
	}

	return m.Login, m.Password, nil
}

// ReadAuthnToken fetches the cached conjur access token. We only do this for OIDC
// since we don't have access to the Conjur API key and this is the only credential we can save.
func (s *NetrcStorageProvider) ReadAuthnToken() ([]byte, error) {
	_, tokenStr, err := s.ReadCredentials()
	if err != nil {
		return nil, err
	}

	return []byte(tokenStr), nil
}

// StoreAuthnToken stores the conjur access token. We only do this for OIDC
// since we don't have access to the Conjur API key and this is the only credential we can save.
func (s *NetrcStorageProvider) StoreAuthnToken(token []byte) error {
	// We should be able to use an empty string for username, but unfortunately
	// this causes panics later on. Instead use a dummy value.
	return s.StoreCredentials("[oidc]", string(token))
}

// PurgeCredentials purges credentials from the specified .netrc file
func (s *NetrcStorageProvider) PurgeCredentials() error {
	// Remove cached credentials (username, api key) from .netrc
	machineName := s.getMachineName()
	filePath := s.netRCPath

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
