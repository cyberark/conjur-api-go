package conjurapi

import (
	"fmt"
	"os"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

type TestUtils interface {
	Client() *Client
	Setup(policy string) error
	SetupWithAuthenticator(authnType string, authenticatorPolicy string, policy string) error
	PolicyBranch() string
	IDWithPath(id string) string
	AdminUser() string
	DefaultTestPolicy() string
}

type BaseTestUtils struct {
	client *Client
}

// We want a sub-path under 'data' to simplify compatibility with Conjur Cloud
// where adding resources under 'root' is restricted
func (b *BaseTestUtils) PolicyBranch() string {
	return "data/test"
}

func (b *BaseTestUtils) IDWithPath(id string) string {
	return b.PolicyBranch() + "/" + id
}

func (b *BaseTestUtils) Client() *Client {
	return b.client
}

type CloudTestUtils struct {
	BaseTestUtils
}

// Setup handles cleaning up resources and loading a test policy into the correct sub-branch (via replace)
func (u *CloudTestUtils) Setup(policy string) error {
	emptyTestBranch := fmt.Sprintf(`
- !policy
  id: test
  owner: !user /%s`, u.AdminUser())

	_, err := u.client.LoadPolicy(
		PolicyModePut,
		"data",
		strings.NewReader(emptyTestBranch),
	)
	if err != nil {
		fmt.Println("Policy load error: ", err)
	}

	_, err = u.client.LoadPolicy(
		PolicyModePut,
		u.PolicyBranch(),
		strings.NewReader(policy),
	)
	if err != nil {
		fmt.Println("Policy load error: ", err)
	}

	return err
}

// SetupWithAuthenticator loads a test policy followed by an authenticator policy
func (u *CloudTestUtils) SetupWithAuthenticator(authnType string, authenticatorPolicy string, policy string) error {
	err := u.Setup(policy)
	if err != nil {
		return err
	}

	// Cloud is preconfigured with empty authenticator policy branches
	authenticatorPath := fmt.Sprintf("conjur/authn-%s", authnType)

	_, err = u.client.LoadPolicy(
		PolicyModePost,
		authenticatorPath,
		strings.NewReader(authenticatorPolicy),
	)

	return err
}

func (u *CloudTestUtils) AdminUser() string {
	return os.Getenv("CONJUR_AUTHN_LOGIN")
}

func (u *CloudTestUtils) DefaultTestPolicy() string {
	return fmt.Sprintf(`
- !host
  id: alice
  owner: !user /%s
  annotations:
    authn/api-key: true
- !host
  id: bob
  owner: !user /%s
  annotations:
    authn/api-key: true

- !variable db-password
- !variable db-password-2
- !variable password

- !permit
  role: !host alice
  privilege: [ execute ]
  resource: !variable db-password

- !policy
  id: prod
  body:
  - !variable cluster-admin
  - !variable cluster-admin-password

  - !policy
    id: database
    body:
    - !variable username
    - !variable password
`, u.AdminUser(), u.AdminUser())
}

type DefaultTestUtils struct {
	BaseTestUtils
}

// Setup handles loading a test policy into the correct sub-branch (via replace)
func (u *DefaultTestUtils) Setup(policy string) error {
	// Ensure we have a 'data/test' policy branch.
	emptyTestBranch := `
- !policy
  id: data
  body:
    - !policy test`

	_, err := u.client.LoadPolicy(
		PolicyModePut,
		"root",
		strings.NewReader(emptyTestBranch),
	)
	if err != nil {
		fmt.Println("Policy load error: ", err)
	}

	_, err = u.client.LoadPolicy(
		PolicyModePut,
		u.PolicyBranch(),
		strings.NewReader(policy),
	)
	if err != nil {
		fmt.Println("Policy load error: ", err)
	}

	return err
}

// SetupWithAuthenticator loads a test policy followed by an authenticator policy
func (u *DefaultTestUtils) SetupWithAuthenticator(authnType string, authenticatorPolicy string, policy string) error {
	err := u.Setup(policy)
	if err != nil {
		return err
	}

	authenticatorPath := fmt.Sprintf("conjur/authn-%s", authnType)
	emptyAuthenticatorBranch := fmt.Sprintf(`
- !policy
  id: %s
`, authenticatorPath)

	// Ensure the policy branch 'conjur/authn-<authnType>' exists
	_, err = u.client.LoadPolicy(
		PolicyModePost,
		"root",
		strings.NewReader(emptyAuthenticatorBranch),
	)
	if err != nil {
		return err
	}

	_, err = u.client.LoadPolicy(
		PolicyModePost,
		authenticatorPath,
		strings.NewReader(authenticatorPolicy),
	)

	return err
}

func (u *DefaultTestUtils) AdminUser() string {
	return "admin"
}

func (u *DefaultTestUtils) DefaultTestPolicy() string {
	return `
- !host alice
- !host bob

- !variable db-password
- !variable db-password-2
- !variable password

- !permit
  role: !host alice
  privilege: [ execute ]
  resource: !variable db-password

- !policy
  id: prod
  body:
  - !variable cluster-admin
  - !variable cluster-admin-password

  - !policy
    id: database
    body:
    - !variable username
    - !variable password
`
}

// Creates a set of test utils depending on which Conjur environment is being used.
//
// OSS/Enterprise - we assume that the env variables include CONJUR_AUTHN_LOGIN and CONJUR_AUTHN_API_KEY
// were populated with the default admin user credentials during Conjur startup.
//
// Cloud - we assume that the env variables include CONJUR_AUTHN_LOGIN and CONJUR_AUTHN_TOKEN
// retrieved during the CI tenant creation process.
func NewTestUtils(config *Config) (TestUtils, error) {
	if config == nil {
		config = &Config{}
	}

	config.mergeEnv()

	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		client, err := NewClientFromEnvironment(*config)
		if err != nil {
			return nil, fmt.Errorf("failed to create cloud client: %w", err)
		}
		return &CloudTestUtils{BaseTestUtils{client: client}}, nil
	}

	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	login := os.Getenv("CONJUR_AUTHN_LOGIN")
	client, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
	if err != nil {
		return nil, fmt.Errorf("failed to create default client: %w", err)
	}
	return &DefaultTestUtils{BaseTestUtils{client: client}}, nil
}
