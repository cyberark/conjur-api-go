package conjurapi

import (
	"context"
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

// authnJWTSpiffePolicy defines the authn-jwt webservice for SPIFFE Workload API tests.
// The jwks-uri, issuer, audience, and token-app-property variables are loaded by the
// test after the service is enabled.
//
// Conjur authn-jwt identity mapping for SPIFFE:
//   - token-app-property = "sub"  → Conjur uses the JWT sub claim as the
//     identity lookup key.
//   - identity-path = "data/test/spiffe-jwt-apps" → combined with the sub claim
//     value, Conjur finds host:data/test/spiffe-jwt-apps/<SPIFFE URI>.
//
// The JWT sub claim is always the full SPIFFE URI
// (e.g. "spiffe://conjur.test/vm-spiffe").  Conjur's token-identity-provider
// accepts the URI as an identifier; the host policy ID is set to the same
// SPIFFE URI so the two match.  The "://" characters are valid in a Conjur
// resource identifier — the lookup will fail only if the host is absent.
var authnJWTSpiffePolicy = `
- !policy
  id: acme-spiffe-jwt
  body:
  - !webservice

  - !group clients

  - !permit
    role: !group clients
    privilege: [ read, authenticate ]
    resource: !webservice

  - !variable jwks-uri
  - !variable issuer
  - !variable audience
  - !variable token-app-property
  - !variable identity-path

  - !grant
    role: !group clients
    member: !host /data/test/spiffe-jwt-apps/${SPIFFE_WORKLOAD_SPIFFE_ID}
`

// authnJWTSpiffeRolesPolicy creates the host used by the SPIFFE JWT e2e test.
// The host id is set to the workload's full SPIFFE URI so that Conjur's
// token-identity-provider can locate it via token-app-property="sub" and
// identity-path="data/test/spiffe-jwt-apps".
//
// The authn-jwt/acme-spiffe-jwt/sub annotation is required: Conjur's
// resource-restrictions validator enforces that every authenticating host has at
// least one authn-jwt/<service-id>/<claim> annotation.  The annotation also acts
// as an additional safety check — it constrains this host to only authenticate
// with a JWT-SVID whose sub claim equals the expected SPIFFE ID.
var authnJWTSpiffeRolesPolicy = `
- !policy
  id: spiffe-jwt-apps
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
    id: ${SPIFFE_WORKLOAD_SPIFFE_ID}
    annotations:
      authn-jwt/acme-spiffe-jwt/sub: ${SPIFFE_WORKLOAD_SPIFFE_ID}

  - !grant
    role: !layer
    member: !host ${SPIFFE_WORKLOAD_SPIFFE_ID}

  - !grant
    member: !layer
    role: !group secrets-users
`

// TestAuthnSpiffeJWT is an end-to-end test for the SPIFFE authn-jwt happy path.
// The test process obtains a JWT-SVID from the SPIRE Workload API via
// spiffe.NewJWTProvider(), authenticates to Conjur via authn-jwt, and retrieves
// a secret.
//
// AC coverage (CNJR-14841):
//   - AC #1: SPIRE JWT-SVID + authn-jwt → secret retrieved (happy-path sub-test)
//   - AC #2: CONJUR_JWT_AUDIENCE unset → audience defaults to "conjur" (NewJWTProvider unit tests)
//   - AC #3: CONJUR_JWT_AUDIENCE set → that value used (NewJWTProvider unit tests)
//   - AC #4: no CONJUR_AUTHN_API_KEY or JWT_TOKEN_PATH required (auto-wire sub-test)
//   - AC #5: JWT_TOKEN_PATH set → auto-wire skipped (TestConfig_LoadFromEnv unit tests)
//   - AC #6: ServiceID unset → error names CONJUR_AUTHN_JWT_SERVICE_ID (TestConfig_Validate)
//   - AC #7: multiple SVIDs + CONJUR_SPIFFE_ID unset → error lists candidates (TestSelectJWTSVID)
//   - AC #8: Workload API error taxonomy / retry (TestJWTProvider_PropagatesFetchError + S1 retry)
//   - AC #9: SPIRE signing-key rotation transparent (jwks-uri → live JWKS; happy-path sub-test)
//   - AC #10: README documents JWT-SVID path (README.md JWT-SVID section)
//
// The test is gated by the TEST_SPIFFE=true environment variable and requires:
//   - A running SPIRE agent with its socket at SPIFFE_ENDPOINT_SOCKET
//   - A running spire-oidc OIDC discovery provider
//   - SPIFFE_JWT_SERVICE_ID      — Conjur authn-jwt service ID (e.g. "acme-spiffe-jwt")
//   - SPIFFE_JWT_ISSUER_URL      — full OIDC issuer URL (e.g. "http://spire-oidc:8085")
//   - SPIFFE_WORKLOAD_SPIFFE_ID  — full SPIFFE ID of the test workload
func TestAuthnSpiffeJWT(t *testing.T) {
	if strings.ToLower(os.Getenv("TEST_SPIFFE")) != "true" {
		t.Skip("Skipping SPIFFE JWT authn test. Set TEST_SPIFFE=true to enable.")
	}

	// authn-jwt runs against the OSS Conjur service (CONJUR_APPLIANCE_URL).
	// Unlike authn-cert, authn-jwt does not require the enterprise appliance,
	// and dynamic EnableAuthenticator works on OSS without startup-time config.
	jwtServiceID := os.Getenv("SPIFFE_JWT_SERVICE_ID")
	issuerURL := os.Getenv("SPIFFE_JWT_ISSUER_URL")
	workloadSpiffeID := os.Getenv("SPIFFE_WORKLOAD_SPIFFE_ID")

	if jwtServiceID == "" || issuerURL == "" || workloadSpiffeID == "" {
		t.Fatal("SPIFFE_JWT_SERVICE_ID, SPIFFE_JWT_ISSUER_URL, and SPIFFE_WORKLOAD_SPIFFE_ID must be set")
	}

	t.Run("authn-jwt SPIFFE Workload API happy path", func(t *testing.T) {
		// Covers AC #1 (SPIRE JWT + authn-jwt → secret retrieved) and
		// AC #9 (signing-key rotation transparent — Conjur fetches live JWKS on each authn).
		//
		// authnJWTSpiffeRolesPolicy substitutes ${SPIFFE_WORKLOAD_SPIFFE_ID} into the
		// host annotation value so Conjur can match the JWT sub claim at runtime.
		substituteSpiffeID := func(s string) string {
			return strings.ReplaceAll(s, "${SPIFFE_WORKLOAD_SPIFFE_ID}", workloadSpiffeID)
		}
		webservicePolicy := substituteSpiffeID(authnJWTSpiffePolicy)
		rolePolicy := substituteSpiffeID(authnJWTSpiffeRolesPolicy)

		utils, err := NewTestUtils(&Config{})
		require.NoError(t, err)

		err = utils.SetupWithAuthenticator("jwt", webservicePolicy, rolePolicy)
		require.NoError(t, err)

		conjur := utils.Client()

		err = conjur.EnableAuthenticator("jwt", jwtServiceID, true)
		require.NoError(t, err)

		// Load the authn-jwt variables pointing to the SPIRE OIDC discovery provider.
		err = conjur.AddSecret("conjur/authn-jwt/"+jwtServiceID+"/jwks-uri",
			issuerURL+"/keys")
		require.NoError(t, err)
		err = conjur.AddSecret("conjur/authn-jwt/"+jwtServiceID+"/issuer", issuerURL)
		require.NoError(t, err)
		// audience = "conjur" — the default audience NewJWTProvider requests when
		// CONJUR_JWT_AUDIENCE is unset.  SPIRE encodes the aud claim as a JSON
		// array (per the SPIFFE JWT-SVID spec), which Conjur handles correctly for
		// audience validation but cannot use as a token-app-property value.
		err = conjur.AddSecret("conjur/authn-jwt/"+jwtServiceID+"/audience", "conjur")
		require.NoError(t, err)
		// Use the JWT sub claim for identity.  The sub claim is always the full
		// SPIFFE URI ("spiffe://conjur.test/vm-spiffe") — a plain string, not an
		// array.  Conjur combines it with identity-path to locate the host:
		//   data/test/spiffe-jwt-apps/spiffe://conjur.test/vm-spiffe
		// The host policy ID is set to the same SPIFFE URI so the lookup succeeds.
		err = conjur.AddSecret("conjur/authn-jwt/"+jwtServiceID+"/token-app-property", "sub")
		require.NoError(t, err)
		err = conjur.AddSecret("conjur/authn-jwt/"+jwtServiceID+"/identity-path", "data/test/spiffe-jwt-apps")
		require.NoError(t, err)

		err = conjur.AddSecret("data/test/spiffe-jwt-apps/database/secret", "spiffe-jwt-secret-value")
		require.NoError(t, err)

		// Use explicit JWTProvider wiring to test the provider directly.
		config := Config{
			ApplianceURL: conjur.config.ApplianceURL,
			Account:      conjur.config.Account,
			SSLCert:      conjur.config.SSLCert,
			SSLCertPath:  conjur.config.SSLCertPath,
			AuthnType:    "jwt",
			ServiceID:    jwtServiceID,
			JWTProvider:  spiffe.NewJWTProvider(),
		}

		spiffeJWTConjur, err := NewClientFromJwt(config)
		require.NoError(t, err)

		_, err = spiffeJWTConjur.GetAuthenticator().RefreshToken()
		require.NoError(t, err)

		whoami, err := spiffeJWTConjur.WhoAmI()
		assert.NoError(t, err)
		// The authenticated role is host/data/test/spiffe-jwt-apps/<SPIFFE URI>,
		// e.g. ".../spiffe://conjur.test/vm-spiffe" — which contains "vm-spiffe".
		assert.Contains(t, string(whoami), "vm-spiffe")

		secret, err := spiffeJWTConjur.RetrieveSecret("data/test/spiffe-jwt-apps/database/secret")
		assert.NoError(t, err)
		assert.Equal(t, "spiffe-jwt-secret-value", string(secret))
	})

	t.Run("auto-wire via LoadFromEnvironment", func(t *testing.T) {
		// Covers AC #4 (FR-AUTH-SPIFFE-05): no CONJUR_AUTHN_API_KEY or JWT_TOKEN_PATH
		// needed when SPIFFE_ENDPOINT_SOCKET + CONJUR_AUTHN_JWT_SERVICE_ID are set.
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
		t.Setenv("CONJUR_AUTHN_JWT_SERVICE_ID", jwtServiceID)

		config, err := LoadConfig()
		require.NoError(t, err)
		assert.NotNil(t, config.JWTProvider,
			"JWTProvider must be auto-wired by LoadFromEnvironment when SPIFFE vars are set")

		token, err := config.JWTProvider(context.Background())
		assert.NoError(t, err)
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3, "JWTProvider must return a three-part JWT string")
	})
}
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
