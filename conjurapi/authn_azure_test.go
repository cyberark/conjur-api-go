package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var authnAzurePolicy = `
- !policy
  id: prod
  body:
  - !webservice

  - !variable
    id: provider-uri

  - !group apps

  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

  # Give the host permission to authenticate using the IAM Authenticator
  - !grant
    role: !group apps
    member: !host /data/test/azure-apps/azureVM
`
var authAzureRolesPolicyTemplate = `
- !policy
  id: azure-apps
  body:
  - &variables
    - !variable database/username
    - !variable database/password
  # Create a group that will have permission to retrieve variables
  - !group secrets-users
  # Give the secrets-users group permission to retrieve variables
  - !permit
    role: !group secrets-users
    privilege: [ read, execute ]
    resource: *variables

  # Create a group to hold this application's hosts
  - !group
  # The host ID needs to match the AWS ARN of the role we wish to authenticate
  - !host
    id: azureVM
    annotations:
      authn-azure/subscription-id: %q
      authn-azure/resource-group: %q
%s
  # Add our host into our group
  - !grant
    role: !group
    member: !host azureVM
  # Give the host in our group permission to retrieve variables
  - !grant
    member: !group
    role: !group secrets-users
`

func TestAzureAuthenticatorRefreshJWT(t *testing.T) {
	authenticator := &authn.AzureAuthenticator{
		JWT: "explicit-token",
		Authenticate: func(jwt string) ([]byte, error) {
			assert.Equal(t, "explicit-token", jwt)
			return []byte("fake-token"), nil
		},
	}

	err := authenticator.RefreshJWT()
	require.NoError(t, err)
	assert.Equal(t, "explicit-token", authenticator.JWT)
}

func TestAuthnAzure(t *testing.T) {
	// Only run this if running on AWS
	if strings.ToLower(os.Getenv("TEST_AZURE")) != "true" {
		t.Skip("Skipping Azure authn test")
	}

	// Ensure required env vars are set
	if os.Getenv("AZURE_SUBSCRIPTION_ID") == "" ||
		os.Getenv("AZURE_RESOURCE_GROUP") == "" ||
		os.Getenv("USER_ASSIGNED_IDENTITY") == "" ||
		os.Getenv("USER_ASSIGNED_IDENTITY_CLIENT_ID") == "" {
		t.Fatal("AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, USER_ASSIGNED_IDENTITY, USER_ASSIGNED_IDENTITY_CLIENT_ID must be set to run this test")
	}

	t.Run("authn-azure system-assigned identity", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		// Replace placeholders in the policy with environment variables
		authAzureRolesPolicy := fmt.Sprintf(authAzureRolesPolicyTemplate,
			os.Getenv("AZURE_SUBSCRIPTION_ID"),
			os.Getenv("AZURE_RESOURCE_GROUP"),
			"")

		err = utils.SetupWithAuthenticator("azure", authnAzurePolicy, authAzureRolesPolicy)
		require.NoError(t, err)
		conjur := utils.Client()

		err = conjur.AddSecret("conjur/authn-azure/prod/provider-uri", "https://sts.windows.net/df242c82-fe4a-47e0-b0f4-e3cb7f8104f1/")
		require.NoError(t, err)
		conjur.EnableAuthenticator("azure", "prod", true)

		err = conjur.AddSecret("data/test/azure-apps/database/username", "secret")
		require.NoError(t, err)
		err = conjur.AddSecret("data/test/azure-apps/database/password", "P@ssw0rd!")
		require.NoError(t, err)

		// EXERCISE
		config := Config{
			ApplianceURL: conjur.config.ApplianceURL,
			Account:      conjur.config.Account,
			AuthnType:    "azure",
			ServiceID:    "prod",
			JWTHostID:    "data/test/azure-apps/azureVM",
		}
		azureConjur, err := NewClientFromAzureCredentials(config)
		require.NoError(t, err)

		_, err = azureConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := azureConjur.WhoAmI()
		assert.NoError(t, err)
		assert.Contains(t, string(whoami), config.JWTHostID)

		secret, err := azureConjur.RetrieveSecret("data/test/azure-apps/database/username")
		assert.NoError(t, err)
		assert.Equal(t, "secret", string(secret))

		secret, err = azureConjur.RetrieveSecret("data/test/azure-apps/database/password")
		assert.NoError(t, err)
		assert.Equal(t, "P@ssw0rd!", string(secret))
	})

	t.Run("authn-azure user-assigned identity", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		// Update host identity annotations based on env variables
		userIdentityAnnotation := fmt.Sprintf(`      authn-azure/user-assigned-identity: "%s"`, os.Getenv("USER_ASSIGNED_IDENTITY"))
		authAzureRolesPolicy := fmt.Sprintf(authAzureRolesPolicyTemplate,
			os.Getenv("AZURE_SUBSCRIPTION_ID"),
			os.Getenv("AZURE_RESOURCE_GROUP"),
			userIdentityAnnotation)

		err = utils.SetupWithAuthenticator("azure", authnAzurePolicy, authAzureRolesPolicy)
		require.NoError(t, err)
		conjur := utils.Client()

		err = conjur.AddSecret("conjur/authn-azure/prod/provider-uri", "https://sts.windows.net/df242c82-fe4a-47e0-b0f4-e3cb7f8104f1/")
		require.NoError(t, err)
		conjur.EnableAuthenticator("azure", "prod", true)

		err = conjur.AddSecret("data/test/azure-apps/database/username", "secret")
		require.NoError(t, err)
		err = conjur.AddSecret("data/test/azure-apps/database/password", "P@ssw0rd!")
		require.NoError(t, err)

		// EXERCISE
		config := Config{
			ApplianceURL:  conjur.config.ApplianceURL,
			Account:       conjur.config.Account,
			AuthnType:     "azure",
			ServiceID:     "prod",
			JWTHostID:     "data/test/azure-apps/azureVM",
			AzureClientID: os.Getenv("USER_ASSIGNED_IDENTITY_CLIENT_ID"),
		}
		azureConjur, err := NewClientFromAzureCredentials(config)
		require.NoError(t, err)

		_, err = azureConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := azureConjur.WhoAmI()
		assert.NoError(t, err)
		assert.Contains(t, string(whoami), config.JWTHostID)

		secret, err := azureConjur.RetrieveSecret("data/test/azure-apps/database/username")
		assert.NoError(t, err)
		assert.Equal(t, "secret", string(secret))

		secret, err = azureConjur.RetrieveSecret("data/test/azure-apps/database/password")
		assert.NoError(t, err)
		assert.Equal(t, "P@ssw0rd!", string(secret))
	})
}

func TestAzureTokenRequest(t *testing.T) {
	t.Run("creates a valid request when client ID is empty", func(t *testing.T) {
		a := &authn.AzureAuthenticator{}
		req, err := a.AzureTokenRequest()
		require.NoError(t, err)
		require.NotNil(t, req)
		assert.Equal(t, "GET", req.Method)
		assert.Equal(t, "true", req.Header.Get("Metadata"))
		assert.Contains(t, req.URL.String(), "resource=https%3A%2F%2Fmanagement.azure.com%2F")
		assert.NotContains(t, req.URL.String(), "client_id=")
	})
	t.Run("creates a valid request when client ID is provided", func(t *testing.T) {
		a := &authn.AzureAuthenticator{
			ClientID: "test-client-id",
		}
		req, err := a.AzureTokenRequest()
		require.NoError(t, err)
		require.NotNil(t, req)
		assert.Equal(t, "GET", req.Method)
		assert.Equal(t, "true", req.Header.Get("Metadata"))
		assert.Contains(t, req.URL.String(), "resource=https%3A%2F%2Fmanagement.azure.com%2F")
		assert.Contains(t, req.URL.String(), "client_id=test-client-id")
	})
}
