package conjurapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var authnGcpPolicy = `
  - !webservice

  - !group apps

  - !permit
    role: !group apps
    privilege: [ read, authenticate ]
    resource: !webservice

  # Give the host permission to authenticate using the GCP Authenticator
  - !grant
    role: !group apps
    member: !host /data/test/gcp-apps/test-app
`
var authGcpRolesPolicy = `
- !policy
  id: gcp-apps
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
  - !host 
    id: test-app
    annotations:
      authn-gcp/project-id: {{ PROJECT_ID }}
  # Add our host into our group
  - !grant
    role: !group
    member: !host test-app
  # Give the host in our group permission to retrieve variables
  - !grant
    member: !group
    role: !group secrets-users
`

func TestGCPAuthenticatorRefreshJWT(t *testing.T) {
	authenticator := &authn.GCPAuthenticator{
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

func TestAuthnGCP(t *testing.T) {
	// Only run this if explicitly enabled
	if strings.ToLower(os.Getenv("TEST_GCP")) != "true" {
		t.Skip("Skipping GCP authn test")
	}

	// Replace placeholder in policy with actual project ID
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		t.Fatal("GCP_PROJECT_ID environment variable is not set")
	}
	authGcpRolesPolicy = strings.ReplaceAll(authGcpRolesPolicy, "{{ PROJECT_ID }}", projectID)

	testCases := []struct {
		name             string
		useExplicitToken bool
	}{
		{
			name:             "Happy path with stubbed metadata server",
			useExplicitToken: false,
		},
		{
			name:             "Happy path with explicit token",
			useExplicitToken: true,
		},
	}

	// Run a stub HTTP server and set the metadata URL to point to it:
	// this is necessary because GCP agents lack Docker runtime,
	// so the test must be run on a non GCP agent (e.g. on AWS).
	const metadataEndpointUri = "/test-identity"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == metadataEndpointUri {
			w.Header().Set(authn.GcpMetadataFlavorHeaderName, authn.GcpMetadataFlavorHeaderValue)
			w.WriteHeader(http.StatusOK)
			gcpToken := os.Getenv("GCP_ID_TOKEN")
			if gcpToken == "" {
				t.Fatal("GCP_ID_TOKEN environment variable is not set")
			}
			w.Write([]byte(gcpToken))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			err = utils.SetupWithAuthenticator("gcp", authnGcpPolicy, authGcpRolesPolicy)
			require.NoError(t, err)
			conjur := utils.Client()
			conjur.EnableAuthenticator("gcp", "", true)

			err = conjur.AddSecret("data/test/gcp-apps/database/username", "secret")
			require.NoError(t, err)
			err = conjur.AddSecret("data/test/gcp-apps/database/password", "P@ssw0rd!")
			require.NoError(t, err)

			// EXERCISE
			jwtContent := ""
			gcpURL := ""
			if tc.useExplicitToken {
				jwtContent = os.Getenv("GCP_ID_TOKEN")
				gcpURL = authn.GcpIdentityURL
			} else {
				gcpURL = server.URL + metadataEndpointUri
			}
			config := Config{
				ApplianceURL: conjur.config.ApplianceURL,
				Account:      conjur.config.Account,
				AuthnType:    "gcp",
				JWTHostID:    "data/test/gcp-apps/test-app",
				JWTContent:   jwtContent,
			}
			gcpConjur, err := NewClientFromGCPCredentials(config, gcpURL)
			require.NoError(t, err)

			_, err = gcpConjur.GetAuthenticator().RefreshToken()
			require.NoError(t, err)

			whoami, err := gcpConjur.WhoAmI()
			assert.NoError(t, err)
			assert.Contains(t, string(whoami), config.JWTHostID)

			secret, err := gcpConjur.RetrieveSecret("data/test/gcp-apps/database/username")
			assert.NoError(t, err)
			assert.Equal(t, "secret", string(secret))

			secret, err = gcpConjur.RetrieveSecret("data/test/gcp-apps/database/password")
			assert.NoError(t, err)
			assert.Equal(t, "P@ssw0rd!", string(secret))
		})
	}
}
