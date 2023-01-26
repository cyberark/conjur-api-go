package conjurapi

import (
	"os"
	"strings"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

var defaultTestPolicy = `
- !user alice
- !host bob

- !variable db-password
- !variable db-password-2
- !variable password

- !permit
  role: !user alice
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

func conjurDefaultSetup() (*Client, error) {
	return conjurSetup(&Config{},  defaultTestPolicy)
}

func conjurSetup(config *Config, policy string) (*Client, error) {
	config.mergeEnv()
	
	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	login := os.Getenv("CONJUR_AUTHN_LOGIN")

	conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})

	if err == nil {
		conjur.LoadPolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)
	}

	return conjur, err
}
