package conjurapi

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientV2_CreateStaticSecretRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	secret := StaticSecret{}
	secret.Name = "Name"
	secret.Branch = "Branch"

	request, err := client.V2().CreateStaticSecretRequest(secret)
	require.NoError(t, err)

	assert.Equal(t, request.Header.Get(v2APIOutgoingHeaderID), v2APIHeader)

	request, err = client.V2().CreateStaticSecretRequest(secret)
	require.NoError(t, err)

	testHost := "localhost/secrets/static"
	assert.Equal(t, request.URL.Path, testHost)

	if request.Method != http.MethodPost {
		t.Errorf("client.V2.GetStaticSecretDetailsRequest method request is wrong. Expected %s used %s", http.MethodPost, request.Method)
		return
	}
}

func TestGetStaticSecretDetailsRequest(t *testing.T) {
	ident := "test/ident"
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	request, err := client.V2().GetStaticSecretDetailsRequest(ident)
	require.NoError(t, err)

	if request == nil {
		t.Errorf("client.V2.GetStaticSecretDetailsRequest data returned nil")
	}

	assert.Equal(t, request.Header.Get(v2APIOutgoingHeaderID), v2APIHeader)

	testHost := "localhost/secrets/static/" + ident
	assert.Equal(t, request.URL.Path, testHost)

	if request.Method != http.MethodGet {
		t.Errorf("client.V2.GetStaticSecretDetailsRequest method request is wrong. Expected %s used %s", http.MethodGet, request.Method)
	}
}

func TestGetStaticSecretPermissionsRequest(t *testing.T) {
	ident := "test/ident"
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)

	request, err := client.V2().GetStaticSecretPermissionsRequest(ident)
	require.NoError(t, err)

	assert.Equal(t, request.Header.Get(v2APIOutgoingHeaderID), v2APIHeader)

	testHost := "localhost/secrets/static/" + ident + "/permissions"
	assert.Equal(t, request.URL.Path, testHost)

	if request.Method != http.MethodGet {
		t.Errorf("client.V2.GetStaticSecretDetailsRequest method request is wrong. Expected %s used %s", http.MethodGet, request.Method)
	}
}

var staticSecretsTestPolicy = `
- !host bob
- !group test-users

- !variable secret

- !permit
  role: !host bob
  privilege: [ execute ]
  resource: !variable secret
`

func TestClientV2_CreateStaticSecret(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(staticSecretsTestPolicy)

	conjur := utils.Client().V2()

	testCases := []struct {
		name        string
		secret      StaticSecret
		expectError string
	}{
		{
			name:        "Add static secret missing privileges",
			secret:      StaticSecret{Branch: "/data/test", Name: "secret2", Permissions: []Permission{{Subject: Subject{Id: "data/test/test-users", Kind: "group"}}}},
			expectError: "privileges",
		},
		{
			name:   "Add static secret",
			secret: StaticSecret{Branch: "/data/test", Name: "secret2", MimeType: "application/json", Permissions: []Permission{{Subject: Subject{Id: "data/test/test-users", Kind: "group"}, Privileges: []string{"read"}}}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			member, err := conjur.CreateStaticSecret(tc.secret)
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {

				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.secret.Name, member.Name)
					assert.Equal(t, tc.secret.Branch, member.Branch)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}
		})
	}
}

func TestClientV2_GetStaticSecretDetails(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(staticSecretsTestPolicy)

	conjur := utils.Client().V2()

	testCases := []struct {
		name        string
		path        string
		secretName  string
		secretPath  string
		secret      StaticSecret
		expectError string
	}{
		{
			name:       "Get static secret details",
			path:       "data/test/secret",
			secretPath: "/data/test",
			secretName: "secret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			member, err := conjur.GetStaticSecretDetails(tc.path)

			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {

				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.secretName, member.Name)
					assert.Equal(t, tc.secretPath, member.Branch)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}
		})
	}
}

func TestClientV2_GetStaticSecretPermissions(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(staticSecretsTestPolicy)

	conjur := utils.Client().V2()

	testCases := []struct {
		name        string
		path        string
		secret      StaticSecret
		expectError string
		permissions string
	}{
		{
			name:        "Get static secret permissions",
			path:        "data/test/secret",
			permissions: "execute",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			member, err := conjur.GetStaticSecretPermissions(tc.path)
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					if tc.permissions != "" {
						assert.Equal(t, member.Permission[0].Privileges[0], tc.permissions)
					}
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}
		})
	}
}
