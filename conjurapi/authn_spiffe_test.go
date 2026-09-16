package conjurapi

import (
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/spiffe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authnSpiffePolicy defines the authn-cert webservice for SPIFFE Workload API tests.
// The trust bundle, host-mode, trust-domain, and identity-path variables are loaded by
// the test after the webservice is enabled.
var authnSpiffePolicy = `
- !policy
  id: acme-spiffe
  body:
  - !webservice

  - !group clients

  - !permit
    role: !group clients
    privilege: [ read, authenticate ]
    resource: !webservice

  - !variable ca-cert
  - !variable host-mode
  - !variable trust-domain
  - !variable identity-path

  - !grant
    role: !group clients
    member: !host /data/test/spiffe-apps/vm-spiffe
`

// authnSpiffeRolesPolicy creates the host and variables used in the SPIFFE e2e test.
var authnSpiffeRolesPolicy = `
- !policy
  id: spiffe-apps
  body:
  - &variables
    - !variable database/secret

  - !group secrets-users

  - !permit
    role: !group secrets-users
    privilege: [ read, execute ]
    resource: *variables

  - !layer

  - !host
    id: vm-spiffe

  - !grant
    role: !layer
    member: !host vm-spiffe

  - !grant
    member: !layer
    role: !group secrets-users
`

// TestAuthnSpiffe is an end-to-end test for the SPIFFE authn-cert happy path:
// the test process obtains an X.509-SVID from the SPIRE Workload API via the
// conjurapi/spiffe provider, authenticates to Conjur, and retrieves a secret.
//
// The test is gated by the TEST_SPIFFE=true environment variable and requires:
//   - A running SPIRE agent with its socket at SPIFFE_ENDPOINT_SOCKET
//   - An enterprise Conjur appliance at CONJUR_CERT_APPLIANCE_URL
//   - SPIFFE_SERVICE_ID  — the Conjur authn-cert service ID (e.g. "acme-spiffe")
//   - SPIFFE_TRUST_BUNDLE — PEM of the SPIRE CA trust bundle
func TestAuthnSpiffe(t *testing.T) {
	if strings.ToLower(os.Getenv("TEST_SPIFFE")) != "true" {
		t.Skip("Skipping SPIFFE authn test. Set TEST_SPIFFE=true to enable.")
	}

	// Redirect the admin client to the enterprise appliance when available.
	if u := os.Getenv("CONJUR_CERT_APPLIANCE_URL"); u != "" {
		t.Setenv("CONJUR_APPLIANCE_URL", u)
	}
	if k := os.Getenv("CONJUR_CERT_AUTHN_API_KEY"); k != "" {
		t.Setenv("CONJUR_AUTHN_API_KEY", k)
	}
	if cert := os.Getenv("CONJUR_CERT_SSL_CERTIFICATE"); cert != "" {
		t.Setenv("CONJUR_SSL_CERTIFICATE", cert)
	}

	serviceID := os.Getenv("SPIFFE_SERVICE_ID")
	trustBundle := os.Getenv("SPIFFE_TRUST_BUNDLE")
	if serviceID == "" || trustBundle == "" {
		t.Fatal("SPIFFE_SERVICE_ID and SPIFFE_TRUST_BUNDLE must be set")
	}

	t.Run("authn-cert SPIFFE Workload API happy path", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		err = utils.SetupWithAuthenticator("cert", authnSpiffePolicy, authnSpiffeRolesPolicy)
		require.NoError(t, err)

		conjur := utils.Client()

		err = conjur.EnableAuthenticator("cert", serviceID, true)
		require.NoError(t, err)

		// Load the SPIRE trust bundle as the CA cert for the authn-cert webservice.
		err = conjur.AddSecret("conjur/authn-cert/"+serviceID+"/ca-cert", trustBundle)
		require.NoError(t, err)

		// Configure the webservice for SPIFFE mode: Conjur will match the SVID SPIFFE ID
		// path against <trust-domain>/<identity-path>/<host-id>.
		err = conjur.AddSecret("conjur/authn-cert/"+serviceID+"/host-mode", "spiffe")
		require.NoError(t, err)
		err = conjur.AddSecret("conjur/authn-cert/"+serviceID+"/trust-domain", "conjur.test")
		require.NoError(t, err)
		err = conjur.AddSecret("conjur/authn-cert/"+serviceID+"/identity-path", "data/test/spiffe-apps")
		require.NoError(t, err)

		err = conjur.AddSecret("data/test/spiffe-apps/database/secret", "spiffe-secret-value")
		require.NoError(t, err)

		config := Config{
			ApplianceURL:       conjur.config.ApplianceURL,
			Account:            conjur.config.Account,
			SSLCert:            conjur.config.SSLCert,
			SSLCertPath:        conjur.config.SSLCertPath,
			AuthnType:          "cert",
			ServiceID:          serviceID,
			ClientCertProvider: spiffe.NewProvider(),
		}

		spiffeConjur, err := NewClientFromCertificate(config)
		require.NoError(t, err)

		_, err = spiffeConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := spiffeConjur.WhoAmI()
		assert.NoError(t, err)
		assert.Contains(t, string(whoami), "vm-spiffe")

		secret, err := spiffeConjur.RetrieveSecret("data/test/spiffe-apps/database/secret")
		assert.NoError(t, err)
		assert.Equal(t, "spiffe-secret-value", string(secret))
	})
}
