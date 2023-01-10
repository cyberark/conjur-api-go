package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenAuthenticator_RefreshToken(t *testing.T) {
	// Test that the RefreshToken method returns the token
	t.Run("Returns token", func(t *testing.T) {
		authenticator := TokenAuthenticator{
			Token: "token",
		}
		token, err := authenticator.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})
}

func TestTokenAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Returns false", func(t *testing.T) {
		// Test that the NeedsTokenRefresh method always returns false
		authenticator := TokenAuthenticator{
			Token: "token",
		}

		assert.False(t, authenticator.NeedsTokenRefresh())
	})
}
