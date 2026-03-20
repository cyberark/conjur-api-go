package conjurapi

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authnCertPolicy defines the authn-cert webservice and its access controls.
// The CA certificate must be loaded into the ca-cert variable before the
// authenticator can be used.
var authnCertPolicy = `
- !policy
  id: acme-vm
  body:
  - !webservice

  - !group clients

  - !permit
    role: !group clients
    privilege: [ read, authenticate ]
    resource: !webservice

  - !variable ca-cert

  - !grant
    role: !group clients
    member: !host /data/test/cert-apps/vm-01
`

// authCertRolesPolicy creates the host and variables used in the cert auth e2e test.
var authCertRolesPolicy = `
- !policy
  id: cert-apps
  body:
  - &variables
    - !variable database/username
    - !variable database/password

  - !group secrets-users

  - !permit
    role: !group secrets-users
    privilege: [ read, execute ]
    resource: *variables

  - !layer

  - !host
    id: vm-01
    annotations:
      authn-cert/cn: vm-01

  - !grant
    role: !layer
    member: !host vm-01

  - !grant
    member: !layer
    role: !group secrets-users
`

func TestAuthnCert(t *testing.T) {
	// Only run when a live Conjur server with authn-cert is available.
	if strings.ToLower(os.Getenv("TEST_CERT")) != "true" {
		t.Skip("Skipping certificate authn test. Set TEST_CERT=true to enable.")
	}

	serviceID := os.Getenv("TEST_CERT_SERVICE_ID")
	if serviceID == "" {
		serviceID = "acme-vm"
	}
	certFile := os.Getenv("CONJUR_AUTHN_CERT_FILE")
	keyFile := os.Getenv("CONJUR_AUTHN_CERT_KEY_FILE")
	caCertContent := os.Getenv("TEST_CERT_CA_CERT")
	if certFile == "" || keyFile == "" || caCertContent == "" {
		t.Fatal("CONJUR_AUTHN_CERT_FILE, CONJUR_AUTHN_CERT_KEY_FILE, and TEST_CERT_CA_CERT must all be set")
	}

	t.Run("authn-cert request mode e2e happy path", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		err = utils.SetupWithAuthenticator("cert", authnCertPolicy, authCertRolesPolicy)
		require.NoError(t, err)

		conjur := utils.Client()
		err = conjur.EnableAuthenticator("cert", serviceID, true)
		require.NoError(t, err)

		// Load the issuer CA certificate into the webservice variable so Conjur
		// can verify client certificates presented during authentication.
		err = conjur.AddSecret("conjur/authn-cert/"+serviceID+"/ca-cert", caCertContent)
		require.NoError(t, err)

		err = conjur.AddSecret("data/test/cert-apps/database/username", "cert-secret")
		require.NoError(t, err)
		err = conjur.AddSecret("data/test/cert-apps/database/password", "P@ssw0rd!")
		require.NoError(t, err)

		config := Config{
			ApplianceURL:      conjur.config.ApplianceURL,
			Account:           conjur.config.Account,
			AuthnType:         "cert",
			ServiceID:         serviceID,
			CertHostID:        "data/test/cert-apps/vm-01",
			ClientCertFile:    certFile,
			ClientCertKeyFile: keyFile,
		}

		certConjur, err := NewClientFromCertificate(config)
		require.NoError(t, err)

		_, err = certConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := certConjur.WhoAmI()
		assert.NoError(t, err)
		assert.Contains(t, string(whoami), "vm-01")

		secret, err := certConjur.RetrieveSecret("data/test/cert-apps/database/username")
		assert.NoError(t, err)
		assert.Equal(t, "cert-secret", string(secret))

		secret, err = certConjur.RetrieveSecret("data/test/cert-apps/database/password")
		assert.NoError(t, err)
		assert.Equal(t, "P@ssw0rd!", string(secret))
	})

	t.Run("authn-cert SPIFFE mode (empty CertHostID)", func(t *testing.T) {
		// SPIFFE mode: the server derives the host identity from the SPIFFE URI SAN
		// in the client certificate. Only run if explicitly enabled because it
		// requires a cert whose SAN matches a Conjur host.
		if strings.ToLower(os.Getenv("TEST_CERT_SPIFFE")) != "true" {
			t.Skip("Skipping SPIFFE mode test. Set TEST_CERT_SPIFFE=true to enable.")
		}

		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		conjur := utils.Client()

		config := Config{
			ApplianceURL:      conjur.config.ApplianceURL,
			Account:           conjur.config.Account,
			AuthnType:         "cert",
			ServiceID:         serviceID,
			CertHostID:        "", // empty → SPIFFE mode; host inferred from cert SAN URI
			ClientCertFile:    certFile,
			ClientCertKeyFile: keyFile,
		}

		certConjur, err := NewClientFromCertificate(config)
		require.NoError(t, err)

		_, err = certConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)
	})
}
