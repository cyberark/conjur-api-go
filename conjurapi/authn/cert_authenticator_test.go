package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertAuthenticator_RefreshToken(t *testing.T) {
	t.Run("Calls Authenticate with configured HostID", func(t *testing.T) {
		authenticator := CertAuthenticator{
			HostID: "vm-workloads/vm-01",
			Authenticate: func(hostID string) ([]byte, error) {
				assert.Equal(t, "vm-workloads/vm-01", hostID)
				return []byte("token"), nil
			},
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})

	t.Run("Calls Authenticate with empty HostID for SPIFFE mode", func(t *testing.T) {
		authenticator := CertAuthenticator{
			HostID: "",
			Authenticate: func(hostID string) ([]byte, error) {
				assert.Equal(t, "", hostID)
				return []byte("spiffe-token"), nil
			},
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, []byte("spiffe-token"), token)
	})

	t.Run("Propagates error from Authenticate", func(t *testing.T) {
		authenticator := CertAuthenticator{
			Authenticate: func(hostID string) ([]byte, error) {
				return nil, assert.AnError
			},
		}

		token, err := authenticator.RefreshToken()

		assert.Error(t, err)
		assert.Nil(t, token)
	})
}

func TestCertAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Returns false", func(t *testing.T) {
		authenticator := CertAuthenticator{}

		assert.False(t, authenticator.NeedsTokenRefresh())
	})
}
