package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOidcAuthenticator_RefreshToken(t *testing.T) {
	// Test that the RefreshToken method calls the Authenticate method
	t.Run("Calls Authenticate", func(t *testing.T) {
		authenticator := OidcAuthenticator{
			Authenticate: func(code, nonce, code_verifier string) ([]byte, error) {
				return []byte("token"), nil
			},
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})
}

func TestOidcAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Returns false", func(t *testing.T) {
		// Test that the NeedsTokenRefresh method always returns false
		authenticator := OidcAuthenticator{}

		assert.False(t, authenticator.NeedsTokenRefresh())
	})
}
