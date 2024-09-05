package authn

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIKeyAuthenticator_RefreshToken(t *testing.T) {
	var login string
	apiKey := "valid-api-key"
	authenticate := func(loginPair LoginPair) ([]byte, error) {
		if loginPair.Login == "valid-login" && loginPair.APIKey == "valid-api-key" {
			return []byte("data"), nil
		} else {
			return nil, fmt.Errorf("401 Invalid")
		}
	}

	t.Run("Given valid credentials returns the token bytes", func(t *testing.T) {
		// file deepcode ignore NoHardcodedCredentials/test: This is a test file
		login := "valid-login"
		authenticator := APIKeyAuthenticator{
			Authenticate: authenticate,
			LoginPair: LoginPair{
				Login:  login,
				APIKey: apiKey,
			},
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Contains(t, string(token), "data")
	})

	t.Run("Given invalid credentials returns nil with error", func(t *testing.T) {
		login = "invalid-login"
		authenticator := APIKeyAuthenticator{
			Authenticate: authenticate,
			LoginPair: LoginPair{
				Login:  login,
				APIKey: apiKey,
			},
		}

		token, err := authenticator.RefreshToken()

		assert.Nil(t, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})
}

func TestAPIKeyAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Returns false", func(t *testing.T) {
		authenticator := APIKeyAuthenticator{}

		assert.False(t, authenticator.NeedsTokenRefresh())
	})
}
