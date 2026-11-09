package conjurapi

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testJWTAuthenticator is a JWT authenticator both servers accept.
func testJWTAuthenticator(name string) *AuthenticatorBase {
	return &AuthenticatorBase{
		Type: "jwt",
		Name: name,
		Data: map[string]interface{}{
			"audience": "conjur-cloud",
			"jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
			"issuer":   "https://token.actions.githubusercontent.com",
			"identity": map[string]interface{}{
				"identity_path":      "data/github-apps",
				"token_app_property": "repository_id",
			},
		},
		Annotations: map[string]string{"description": "kept by a patch"},
	}
}

// newTestAuthenticators creates count JWT authenticators with unique names and
// deletes them when the test ends.
func newTestAuthenticators(t *testing.T, count int) (*Client, []string) {
	t.Helper()
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	SkipIfUnsupported(t, utils.Client(), contract.CapabilityAuthenticatorsV2)

	// Secrets Manager SaaS already has the conjur/authn-jwt branch, and Setup
	// would also empty data/test, which these tests don't use.
	if !isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		require.NoError(t, utils.SetupWithAuthenticator("jwt", jwtAuthenticatorPolicy, jwtRolePolicy))
	}
	conjur := utils.Client()

	prefix := fmt.Sprintf("test-authn-%d", time.Now().UnixNano())
	var names []string
	for i := range count {
		name := fmt.Sprintf("%s-%d", prefix, i)
		_, err := conjur.V2().CreateAuthenticator(testJWTAuthenticator(name))
		require.NoError(t, err)
		names = append(names, name)
		t.Cleanup(func() {
			assert.NoError(t, conjur.V2().DeleteAuthenticator("jwt", name))
		})
	}
	return conjur, names
}

func TestClientV2_UpdateAuthenticator(t *testing.T) {
	conjur, names := newTestAuthenticators(t, 1)
	name := names[0]

	t.Run("Disables and enables it by combined ID", func(t *testing.T) {
		require.NoError(t, conjur.SetAuthenticatorEnabled("authn-jwt/"+name, false))
		got, err := conjur.V2().GetAuthenticator("jwt", name)
		require.NoError(t, err)
		assert.False(t, normalize(got).Enabled)

		require.NoError(t, conjur.SetAuthenticatorEnabled("authn-jwt/"+name, true))
		got, err = conjur.V2().GetAuthenticator("jwt", name)
		require.NoError(t, err)
		assert.True(t, normalize(got).Enabled)
	})

	t.Run("Changes only the annotations and data it sends", func(t *testing.T) {
		patch := &AuthenticatorPatch{
			Annotations: map[string]string{"owner-team": "sdk"},
			Data: map[string]interface{}{
				"audience": "patched-audience",
				"identity": map[string]interface{}{"token_app_property": "sub"},
			},
		}
		if !conjur.config.IsSaaS() {
			_, err := conjur.V2().UpdateAuthenticator("jwt", name, patch)
			assert.ErrorContains(t, err, `only "enabled" can be changed`)
			return
		}

		_, err := conjur.V2().UpdateAuthenticator("jwt", name, patch)
		require.NoError(t, err)

		got, err := conjur.V2().GetAuthenticator("jwt", name)
		require.NoError(t, err)
		assert.Equal(t, "patched-audience", got.Data["audience"])
		assert.Equal(t, "https://token.actions.githubusercontent.com", got.Data["issuer"])
		// A nested key is merged too: identity_path stays.
		assert.Equal(t, map[string]interface{}{
			"identity_path":      "data/github-apps",
			"token_app_property": "sub",
		}, got.Data["identity"])
		assert.Equal(t, "sdk", got.Annotations["owner-team"])
		assert.Equal(t, "kept by a patch", got.Annotations["description"])
		assert.True(t, normalize(got).Enabled)
	})

	t.Run("Rejects an unknown data key with a 422", func(t *testing.T) {
		if !conjur.config.IsSaaS() {
			t.Skip("Self-Hosted refuses any data patch before sending it")
		}

		_, err := conjur.V2().UpdateAuthenticator("jwt", name, &AuthenticatorPatch{
			Data: map[string]interface{}{"no_such_key": "x"},
		})
		var conjurErr *response.ConjurError
		require.ErrorAs(t, err, &conjurErr)
		assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
		assert.Contains(t, err.Error(), "Unexpected parameters: no_such_key")
	})
}

func TestClientV2_CreateAuthenticator_DuplicateConflicts(t *testing.T) {
	conjur, names := newTestAuthenticators(t, 1)

	_, err := conjur.V2().CreateAuthenticator(testJWTAuthenticator(names[0]))
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	assert.Equal(t, http.StatusConflict, conjurErr.Code)
	assert.Contains(t, err.Error(), "already exists.")
}

func TestClientV2_ListAuthenticators_IgnoresPagingOnSaaS(t *testing.T) {
	if !isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Skip("Skipping SaaS authenticator paging test for on-prem")
	}
	conjur, names := newTestAuthenticators(t, 3)
	var created []string
	for _, name := range names {
		created = append(created, "jwt/"+name)
	}

	ids := func(list *AuthenticatorListResponse) []string {
		var ids []string
		for _, a := range list.Authenticators {
			ids = append(ids, a.Type+"/"+a.Name)
		}
		return ids
	}

	all, err := conjur.V2().ListAuthenticators(nil)
	require.NoError(t, err)
	assert.Subset(t, ids(all), created)
	assert.Equal(t, len(all.Authenticators), all.Count)

	// Secrets Manager SaaS ignores limit and offset for now, so a page is the
	// whole list and Count is its length: all three of the test's
	// authenticators are on a page of two. Other jobs may change the tenant's
	// list between calls, so only the test's own authenticators are compared.
	// Once the server pages properly, change this to check that the pages add
	// up to the whole list, in order.
	filter := &AuthenticatorFilter{Limit: 2, Offset: 1}
	page, err := conjur.V2().ListAuthenticators(filter)
	require.NoError(t, err)
	assert.Subset(t, ids(page), created)
	assert.Equal(t, len(page.Authenticators), page.Count)
}
