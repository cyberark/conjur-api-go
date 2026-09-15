package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getAuthnIamRole() string {
	if role := os.Getenv("AUTHN_IAM_TEST_ROLE"); role != "" {
		return role
	}
	return "InstanceReadJenkinsExecutorHostFactoryToken"
}

func getAuthnIamPolicy(role string) string {
	return fmt.Sprintf(`
- !policy
  id: prod
  body:
  - !webservice

  - !group clients

  - !permit
    role: !group clients
    privilege: [ read, authenticate ]
    resource: !webservice

  # Give the host permission to authenticate using the IAM Authenticator
  - !grant
    role: !group clients
    member: !host /data/test/myspace/601277729239/%s
`, role)
}

func getAuthIamRolesPolicy(role string) string {
	return fmt.Sprintf(`
- !policy
  id: myspace
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

  # Create a layer to hold this application's hosts
  - !layer
  # The host ID needs to match the AWS ARN of the role we wish to authenticate
  - !host 601277729239/%s
  # Add our host into our layer
  - !grant
    role: !layer
    member: !host 601277729239/%s
  # Give the host in our layer permission to retrieve variables
  - !grant
    member: !layer
    role: !group secrets-users
`, role, role)
}

func TestAuthnIam(t *testing.T) {
	// Only run this if running on AWS
	if strings.ToLower(os.Getenv("TEST_AWS")) != "true" {
		t.Skip("Skipping AWS IAM authn test")
	}

	t.Run("authn-iam e2e happy path", func(t *testing.T) {
		role := getAuthnIamRole()
		jwtHostID := fmt.Sprintf("data/test/myspace/601277729239/%s", role)

		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		err = utils.SetupWithAuthenticator("iam", getAuthnIamPolicy(role), getAuthIamRolesPolicy(role))
		require.NoError(t, err)
		conjur := utils.Client()
		conjur.EnableAuthenticator("iam", "prod", true)

		err = conjur.AddSecret("data/test/myspace/database/username", "secret")
		require.NoError(t, err)
		err = conjur.AddSecret("data/test/myspace/database/password", "P@ssw0rd!")
		require.NoError(t, err)

		// EXERCISE
		config := Config{
			ApplianceURL: conjur.config.ApplianceURL,
			Account:      conjur.config.Account,
			AuthnType:    "iam",
			ServiceID:    "prod",
			JWTHostID:    jwtHostID,
		}
		iamConjur, err := NewClientFromAWSCredentials(config)
		require.NoError(t, err)

		_, err = iamConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := iamConjur.WhoAmI()
		assert.NoError(t, err)
		assert.Contains(t, string(whoami), config.JWTHostID)

		secret, err := iamConjur.RetrieveSecret("data/test/myspace/database/username")
		assert.NoError(t, err)
		assert.Equal(t, "secret", string(secret))

		secret, err = iamConjur.RetrieveSecret("data/test/myspace/database/password")
		assert.NoError(t, err)
		assert.Equal(t, "P@ssw0rd!", string(secret))
	})
}
