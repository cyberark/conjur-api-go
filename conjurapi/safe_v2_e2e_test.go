package conjurapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSafeClient returns a V2 client for the live tests, which run only on
// Secrets Manager SaaS.
func newTestSafeClient(t *testing.T) *ClientV2 {
	t.Helper()
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	client := utils.Client()
	if !client.config.IsSaaS() {
		t.Skip("Skipping off Secrets Manager SaaS: safes are SaaS-only")
	}
	return client.V2()
}

// newTestSafeName returns a safe name that no other test or run uses.
func newTestSafeName() string {
	return fmt.Sprintf("test-sdk-safe-%d", time.Now().UnixNano())
}

// newLiveSafe creates safe and deletes it when the test ends.
func newLiveSafe(t *testing.T, conjur *ClientV2, safe Safe) *Safe {
	t.Helper()
	// Registered before the create, so a create that fails after the safe
	// was made still cleans up.
	t.Cleanup(func() {
		ignoreSafeNotFound(t, conjur.DeleteSafe(safe.Type, safe.Name), "delete the test safe %s/%s", safe.Type, safe.Name)
	})
	created, err := conjur.CreateSafe(safe)
	require.NoError(t, err, "create the test safe %s/%s", safe.Type, safe.Name)
	return created
}

// ignoreSafeNotFound accepts a cleanup that worked or found nothing to remove.
func ignoreSafeNotFound(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	var conjurErr *response.ConjurError
	if !errors.As(err, &conjurErr) || conjurErr.Code != http.StatusNotFound {
		assert.NoError(t, err, msgAndArgs...)
	}
}

// requireSafeStatus requires err to be a *response.ConjurError with the given
// HTTP status and, unless code is empty, the given error code.
func requireSafeStatus(t *testing.T, err error, status int, code string, msgAndArgs ...any) {
	t.Helper()
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr, msgAndArgs...)
	require.Equal(t, status, conjurErr.Code, msgAndArgs...)
	if code != "" {
		require.NotNil(t, conjurErr.Details, msgAndArgs...)
		assert.Equal(t, code, conjurErr.Details.Code, msgAndArgs...)
	}
}

// listAllSafes walks every page of the safe list for filter, 1000 at a time.
func listAllSafes(t *testing.T, conjur *ClientV2, filter SafeFilter) []Safe {
	t.Helper()
	filter.Limit = 1000
	var all []Safe
	for page := 0; page < 20; page++ {
		filter.Offset = page * filter.Limit
		list, err := conjur.ListSafes(&filter)
		require.NoError(t, err, "list the safes at offset %d", filter.Offset)
		all = append(all, list.Safes...)
		if filter.Offset+len(list.Safes) >= list.Count {
			return all
		}
	}
	require.FailNow(t, "the safe list has more than 20 pages")
	return nil
}

// safeSubURL is the URL of a route under a safe, such as its permissions.
func safeSubURL(t *testing.T, conjur *ClientV2, safe Safe, parts ...string) string {
	t.Helper()
	safeURL, err := conjur.safeURL(safe.Type, safe.Name)
	require.NoError(t, err)
	return safeURL + "/" + strings.Join(parts, "/")
}

// The helpers below send the requests themselves: this branch has no call for
// a secret made through the safe's route, and no safe kind in the permission
// calls. Switch the last three to GrantPermission, RevokePermission and
// ListPermissions with PermissionKindSafe once CNJR-15230 lands.

// createSafeScopedSecret creates a static secret through the safe's own route,
// POST /safes/<type>/<name>/secrets.
func createSafeScopedSecret(t *testing.T, conjur *ClientV2, safe Safe, secret, value string) {
	t.Helper()
	req, err := newV2JSONRequest(http.MethodPost, safeSubURL(t, conjur, safe, "secrets"),
		map[string]string{"name": secret, "value": value}, v2APIHeaderBeta)
	require.NoError(t, err)
	_, err = submitAndReadData(conjur, req)
	require.NoError(t, err, "create the secret %s in the safe %s/%s", secret, safe.Type, safe.Name)
}

func grantSafePermission(t *testing.T, conjur *ClientV2, safe Safe, subject Subject, privileges []string) {
	t.Helper()
	req, err := newV2JSONRequest(http.MethodPost, safeSubURL(t, conjur, safe, "permissions"),
		Permission{Subject: subject, Privileges: privileges}, v2APIHeaderBeta)
	require.NoError(t, err)
	_, err = submitAndReadData(conjur, req)
	require.NoError(t, err, "grant %s on the safe %s/%s", subject.Id, safe.Type, safe.Name)
}

func revokeSafePermission(t *testing.T, conjur *ClientV2, safe Safe, subject Subject) {
	t.Helper()
	req, err := newV2Request(http.MethodDelete, safeSubURL(t, conjur, safe, "permissions", subject.Kind, subject.Id), v2APIHeaderBeta)
	require.NoError(t, err)
	require.NoError(t, submitAndEmpty(conjur, req), "revoke %s on the safe %s/%s", subject.Id, safe.Type, safe.Name)
}

func listSafePermissions(t *testing.T, conjur *ClientV2, safe Safe) *PermissionResponse {
	t.Helper()
	req, err := newV2Request(http.MethodGet, safeSubURL(t, conjur, safe, "permissions"), v2APIHeaderBeta)
	require.NoError(t, err)
	list, err := submitAndUnmarshal[PermissionResponse](conjur, req)
	require.NoError(t, err, "list the permissions on the safe %s/%s", safe.Type, safe.Name)
	return list
}

// workloadAPIKey returns the API key from a CreateWorkload response.
func workloadAPIKey(body []byte) (string, bool) {
	var workload Workload
	if json.Unmarshal(body, &workload) != nil {
		return "", false
	}
	for _, descriptor := range workload.AuthnDescriptors {
		if descriptor.Type == "api_key" {
			key, ok := descriptor.Data["value"].(string)
			return key, ok && key != ""
		}
	}
	return "", false
}

func TestClientV2_Safes_CRUD(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()

	for _, safeType := range []string{"static", "dynamic", "managed"} {
		t.Run(safeType, func(t *testing.T) {
			annotations := map[string]string{"team": "sdk-tests"}
			created := newLiveSafe(t, conjur, Safe{Type: safeType, Name: name, Environment: "test", Description: "SDK test safe", Annotations: annotations})
			assert.Equal(t, safeType, created.Type)
			assert.Equal(t, name, created.Name)
			assert.Equal(t, "test", created.Environment)
			assert.Equal(t, "SDK test safe", created.Description)
			assert.Equal(t, annotations, created.Annotations)
			assert.NotEmpty(t, created.CreatedAt)
			require.NotNil(t, created.Replicated)
			assert.False(t, *created.Replicated)
			assert.Nil(t, created.SecretsCount, "secrets_count comes only with the extended projection")

			got, err := conjur.GetSafe(safeType, name)
			require.NoError(t, err)
			assert.Equal(t, *created, *got)

			extended, err := conjur.GetSafeExtended(safeType, name)
			require.NoError(t, err)
			require.NotNil(t, extended.SecretsCount)
			assert.Equal(t, 0, *extended.SecretsCount)

			// A partial update: what isn't sent is kept, and annotations merge.
			updated, err := conjur.UpdateSafe(Safe{Type: safeType, Name: name, Description: "updated", Annotations: map[string]string{"owner": "sdk"}})
			require.NoError(t, err)
			merged := map[string]string{"team": "sdk-tests", "owner": "sdk"}
			assert.Equal(t, "updated", updated.Description)
			assert.Equal(t, "test", updated.Environment)
			assert.Equal(t, merged, updated.Annotations)
			got, err = conjur.GetSafe(safeType, name)
			require.NoError(t, err)
			assert.Equal(t, "updated", got.Description)
			assert.Equal(t, "test", got.Environment)
			assert.Equal(t, merged, got.Annotations)

			// A full replace: what isn't sent is cleared.
			replaced, err := conjur.ReplaceSafe(Safe{Type: safeType, Name: name, Description: "replaced"})
			require.NoError(t, err)
			assert.Equal(t, "replaced", replaced.Description)
			assert.Empty(t, replaced.Environment)
			assert.Empty(t, replaced.Annotations)
			got, err = conjur.GetSafe(safeType, name)
			require.NoError(t, err)
			assert.Equal(t, "replaced", got.Description)
			assert.Empty(t, got.Environment)
			assert.Empty(t, got.Annotations)

			_, err = conjur.ReplaceSafe(Safe{Type: safeType, Name: name})
			require.NoError(t, err)
			got, err = conjur.GetSafe(safeType, name)
			require.NoError(t, err)
			assert.Empty(t, got.Description)
			assert.Empty(t, got.Environment)
			assert.Empty(t, got.Annotations)

			require.NoError(t, conjur.DeleteSafe(safeType, name))
			_, err = conjur.GetSafe(safeType, name)
			requireSafeStatus(t, err, http.StatusNotFound, "not_found", "read after the delete")
			requireSafeStatus(t, conjur.DeleteSafe(safeType, name), http.StatusNotFound, "not_found", "delete again")
		})
	}
}

func TestClientV2_Safes_CreateRejected(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()

	t.Run("duplicate", func(t *testing.T) {
		newLiveSafe(t, conjur, Safe{Type: "static", Name: name})
		_, err := conjur.CreateSafe(Safe{Type: "static", Name: name})
		requireSafeStatus(t, err, http.StatusConflict, "conflict")
		assert.ErrorContains(t, err, "already exists")
	})

	// Every name holds name, so one the service accepts by mistake can't
	// collide with another run.
	for _, tc := range []struct {
		label string
		safe  Safe
		text  string
	}{
		{"unknown type", Safe{Type: "bogus", Name: name + "-type"}, "is not allowed"},
		{"empty segment", Safe{Type: "static", Name: name + "//b"}, "Invalid 'name'"},
		{"leading slash", Safe{Type: "static", Name: "/" + name}, "Invalid 'name'"},
		{"trailing slash", Safe{Type: "static", Name: name + "/"}, "Invalid 'name'"},
		{"space", Safe{Type: "static", Name: name + " b"}, "Invalid 'name'"},
		{"dot", Safe{Type: "static", Name: name + ".b"}, "Invalid 'name'"},
		{"non-ASCII letter", Safe{Type: "static", Name: name + "ü"}, "Invalid 'name'"},
		{"257 characters", Safe{Type: "static", Name: name + strings.Repeat("a", 257-len(name))}, "maximum length of 256"},
		{"secrets segment", Safe{Type: "static", Name: name + "/secrets"}, "cannot include 'secrets'"},
		{"delegation at the end", Safe{Type: "static", Name: name + "/delegation"}, "cannot end with '/delegation'"},
		{"129-character description", Safe{Type: "static", Name: name + "-desc", Description: strings.Repeat("d", 129)}, "length exceeded"},
		{"markup in the description", Safe{Type: "static", Name: name + "-markup", Description: "<b>"}, "Invalid 'description'"},
		{"empty annotation value", Safe{Type: "static", Name: name + "-value", Annotations: map[string]string{"k": ""}}, "annotation value"},
		{"empty annotation name", Safe{Type: "static", Name: name + "-key", Annotations: map[string]string{"": "v"}}, "annotation name"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			_, err := conjur.CreateSafe(tc.safe)
			if err == nil {
				// DeleteSafe refuses some of these names before sending.
				_ = conjur.DeleteSafe(tc.safe.Type, tc.safe.Name)
				t.Fatalf("the service accepted the safe %s/%q", tc.safe.Type, tc.safe.Name)
			}
			requireSafeStatus(t, err, http.StatusUnprocessableEntity, "unprocessable_entity")
			assert.ErrorContains(t, err, tc.text)
		})
	}

	t.Run("256 characters", func(t *testing.T) {
		newLiveSafe(t, conjur, Safe{Type: "static", Name: name + strings.Repeat("a", 256-len(name))})
	})

	t.Run("checked before sending", func(t *testing.T) {
		var conjurErr *response.ConjurError
		_, err := conjur.CreateSafe(Safe{Type: "static"})
		require.Error(t, err)
		assert.False(t, errors.As(err, &conjurErr), "the SDK refuses an empty name itself")
		_, err = conjur.CreateSafe(Safe{Name: name + "-no-type"})
		require.Error(t, err)
		assert.False(t, errors.As(err, &conjurErr), "the SDK refuses an empty type itself")
	})

	t.Run("markup after the first line", func(t *testing.T) {
		// The service checks the description line by line, so this is
		// accepted. This pins today's behaviour.
		created := newLiveSafe(t, conjur, Safe{Type: "static", Name: name + "-lines", Description: "ok\n<b>x</b>"})
		assert.Equal(t, "ok\n<b>x</b>", created.Description)
	})
}

func TestClientV2_Safes_NotFound(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()
	newLiveSafe(t, conjur, Safe{Type: "static", Name: name})

	for _, tc := range []struct{ label, safeType, name string }{
		{"missing name", "static", name + "-missing"},
		{"existing name, other type", "dynamic", name},
	} {
		t.Run(tc.label, func(t *testing.T) {
			_, err := conjur.GetSafe(tc.safeType, tc.name)
			requireSafeStatus(t, err, http.StatusNotFound, "not_found", "GetSafe")
			_, err = conjur.GetSafeExtended(tc.safeType, tc.name)
			requireSafeStatus(t, err, http.StatusNotFound, "not_found", "GetSafeExtended")
			_, err = conjur.UpdateSafe(Safe{Type: tc.safeType, Name: tc.name, Description: "d"})
			requireSafeStatus(t, err, http.StatusNotFound, "not_found", "UpdateSafe")
			_, err = conjur.ReplaceSafe(Safe{Type: tc.safeType, Name: tc.name, Description: "d"})
			requireSafeStatus(t, err, http.StatusNotFound, "not_found", "ReplaceSafe")
			requireSafeStatus(t, conjur.DeleteSafe(tc.safeType, tc.name), http.StatusNotFound, "not_found", "DeleteSafe")
		})
	}

	_, err := conjur.GetSafe("static", name)
	assert.NoError(t, err, "the static safe is still there")
}

func TestClientV2_Safes_List(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()
	for _, safe := range []Safe{
		{Type: "static", Name: name + "-1"},
		{Type: "static", Name: name + "-2"},
		{Type: "dynamic", Name: name + "-3"},
	} {
		newLiveSafe(t, conjur, safe)
	}
	// Other runs add and delete safes on the same tenant, so the checks walk
	// whole lists and only look for these three.
	ours := func(safes []Safe) []string {
		var found []string
		for _, safe := range safes {
			if strings.HasPrefix(safe.Name, name+"-") {
				found = append(found, safe.Type+"/"+safe.Name)
			}
		}
		return found
	}
	static := []string{"static/" + name + "-1", "static/" + name + "-2"}
	dynamic := []string{"dynamic/" + name + "-3"}

	t.Run("all", func(t *testing.T) {
		assert.ElementsMatch(t, append(static, dynamic...), ours(listAllSafes(t, conjur, SafeFilter{})))
	})

	t.Run("paging", func(t *testing.T) {
		filter := &SafeFilter{Limit: 2}
		page, err := conjur.ListSafes(filter)
		require.NoError(t, err)
		assert.Len(t, page.Safes, 2)
		assert.GreaterOrEqual(t, page.Count, 3, "count is the total, not the page size")

		filter = &SafeFilter{Limit: 1000, Offset: 100000}
		page, err = conjur.ListSafes(filter)
		require.NoError(t, err)
		assert.Empty(t, page.Safes)
	})

	t.Run("extended", func(t *testing.T) {
		all := listAllSafes(t, conjur, SafeFilter{Extended: true})
		assert.ElementsMatch(t, append(static, dynamic...), ours(all))
		for _, safe := range all {
			assert.NotNil(t, safe.SecretsCount, "secrets_count of %s/%s", safe.Type, safe.Name)
		}
	})

	t.Run("safe type", func(t *testing.T) {
		for safeType, want := range map[string][]string{"static": static, "dynamic": dynamic} {
			all := listAllSafes(t, conjur, SafeFilter{SafeType: safeType})
			assert.ElementsMatch(t, want, ours(all), "ours in the %s list", safeType)
			for _, safe := range all {
				assert.Equal(t, safeType, safe.Type, "%s in the %s list", safe.Name, safeType)
			}
		}
		_, err := conjur.ListSafes(&SafeFilter{SafeType: "bogus"})
		requireSafeStatus(t, err, http.StatusUnprocessableEntity, "unprocessable_entity")
		assert.ErrorContains(t, err, "must be one of")
	})

	t.Run("limit over 1000", func(t *testing.T) {
		_, err := conjur.ListSafes(&SafeFilter{Limit: 1001})
		requireSafeStatus(t, err, http.StatusUnprocessableEntity, "unprocessable_entity")
		assert.ErrorContains(t, err, "must not exceed 1000")
	})
}

func TestClientV2_Safes_Branches(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()

	// The same name works in each type, because each type has its own branch.
	for _, tc := range []struct{ safeType, parent string }{
		{"static", "data/static"},
		{"dynamic", "data/dynamic"},
		{"managed", "data/vault"},
	} {
		newLiveSafe(t, conjur, Safe{Type: tc.safeType, Name: name})
		branch, err := conjur.ReadBranch(tc.parent + "/" + name)
		require.NoError(t, err, "read the %s safe's branch", tc.safeType)
		assert.Equal(t, name, branch.Name)
		assert.Equal(t, tc.parent, branch.Branch)
	}
	_, err := conjur.ReadBranch("data/managed/" + name)
	requireSafeStatus(t, err, http.StatusNotFound, "not_found")

	// The safe's branch is protected.
	err = conjur.DeleteBranch("data/static/" + name)
	requireSafeStatus(t, err, http.StatusForbidden, "forbidden")
	assert.ErrorContains(t, err, "protected branch")
	_, err = conjur.GetSafe("static", name)
	assert.NoError(t, err, "the safe is still there")
}

func TestClientV2_Safes_NestedNames(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()
	parent := Safe{Type: "static", Name: name}
	newLiveSafe(t, conjur, parent)

	t.Run("route clash", func(t *testing.T) {
		// A nested name ending in permissions or components is sent as one
		// segment (%2F), so it reaches the safe and not the parent's route of
		// that name.
		grants := func() []string {
			var set []string
			for _, p := range listSafePermissions(t, conjur, parent).Permission {
				set = append(set, fmt.Sprintf("%s %s %v", p.Subject.Kind, p.Subject.Id, slices.Sorted(slices.Values(p.Privileges))))
			}
			return set
		}
		before := grants()

		for _, last := range []string{"permissions", "components"} {
			clash := Safe{Type: "static", Name: name + "/" + last}
			newLiveSafe(t, conjur, clash)
			listed := false
			for _, safe := range listAllSafes(t, conjur, SafeFilter{SafeType: "static"}) {
				listed = listed || safe.Name == clash.Name
			}
			assert.True(t, listed, "%s is listed", clash.Name)

			got, err := conjur.GetSafe(clash.Type, clash.Name)
			require.NoError(t, err, "get %s", clash.Name)
			assert.Equal(t, clash.Name, got.Name)
			extended, err := conjur.GetSafeExtended(clash.Type, clash.Name)
			require.NoError(t, err, "get %s extended", clash.Name)
			assert.NotNil(t, extended.SecretsCount)
			updated, err := conjur.UpdateSafe(Safe{Type: clash.Type, Name: clash.Name, Description: "d"})
			require.NoError(t, err, "update %s", clash.Name)
			assert.Equal(t, clash.Name, updated.Name)
			replaced, err := conjur.ReplaceSafe(Safe{Type: clash.Type, Name: clash.Name, Description: "d"})
			require.NoError(t, err, "replace %s", clash.Name)
			assert.Equal(t, clash.Name, replaced.Name)

			require.NoError(t, conjur.DeleteSafe(clash.Type, clash.Name), "delete %s", clash.Name)
			_, err = conjur.GetSafe(clash.Type, clash.Name)
			requireSafeStatus(t, err, http.StatusNotFound, "")
		}
		assert.ElementsMatch(t, before, grants(), "the parent's grants are unchanged")
		got, err := conjur.GetSafe(parent.Type, parent.Name)
		require.NoError(t, err, "the parent is still there")
		assert.Empty(t, got.Description, "the parent wasn't updated")
	})

	t.Run("nested safe", func(t *testing.T) {
		// A nested name is a safe of its own, with its own branch, and
		// deleting the parent keeps it.
		nested := Safe{Type: "static", Name: name + "/sub"}
		newLiveSafe(t, conjur, nested)
		branch, err := conjur.ReadBranch("data/static/" + nested.Name)
		require.NoError(t, err)
		assert.Equal(t, nested.Name, branch.Name)
		assert.Equal(t, "data/static", branch.Branch)

		require.NoError(t, conjur.DeleteSafe(parent.Type, parent.Name))
		_, err = conjur.GetSafe(nested.Type, nested.Name)
		assert.NoError(t, err, "the nested safe is still there")
	})
}

func TestClientV2_Safes_DeleteWithSecrets(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()
	newLiveSafe(t, conjur, Safe{Type: "static", Name: name})
	branch := "data/static/" + name
	_, err := conjur.CreateStaticSecret(StaticSecret{Branch: branch, Name: "s1", Value: "test-sdk-safe-value"})
	require.NoError(t, err, "create the secret s1")

	safe, err := conjur.GetSafeExtended("static", name)
	require.NoError(t, err)
	require.NotNil(t, safe.SecretsCount)
	assert.Equal(t, 1, *safe.SecretsCount)

	// The ticket asks for an error when the safe holds secrets, but the
	// service deletes the safe and its secrets. This pins today's behaviour;
	// change it if the service starts refusing.
	require.NoError(t, conjur.DeleteSafe("static", name))
	_, err = conjur.GetSafe("static", name)
	requireSafeStatus(t, err, http.StatusNotFound, "not_found", "the safe is gone")
	_, err = conjur.GetStaticSecretDetails(branch + "/s1")
	requireSafeStatus(t, err, http.StatusNotFound, "not_found", "the secret is gone")
}

func TestClientV2_Safes_ConsumerAccess(t *testing.T) {
	conjur := newTestSafeClient(t)
	name := newTestSafeName()

	_, err := conjur.CreateBranch(Branch{Branch: "data", Name: name})
	require.NoError(t, err, "create the test branch")
	branch := "data/" + name
	t.Cleanup(func() {
		err := conjur.DeleteBranch(branch)
		ignoreSafeNotFound(t, err, "delete the test branch")
	})
	_, err = conjur.CreateGroup(Group{Branch: branch, Name: "readers"})
	require.NoError(t, err, "create the group readers")
	readers := branch + "/readers"

	created, err := conjur.CreateWorkload(Workload{Branch: branch, Name: "wl-reader", AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}}})
	require.NoError(t, err, "create the workload wl-reader")
	// The response holds the API key, so it never goes into a message.
	apiKey, ok := workloadAPIKey(created)
	require.True(t, ok, "the workload has an API key")

	// GroupMember has no workload kind; the service takes host for one.
	member := GroupMember{ID: branch + "/wl-reader", Kind: "host"}
	_, err = conjur.AddGroupMember(readers, member)
	require.NoError(t, err, "add wl-reader to readers")
	t.Cleanup(func() {
		_, err := conjur.RemoveGroupMember(readers, member)
		ignoreSafeNotFound(t, err, "remove wl-reader from readers")
	})

	safe := Safe{Type: "static", Name: name}
	newLiveSafe(t, conjur, safe)
	safeBranch := "data/static/" + name
	createSafeScopedSecret(t, conjur, safe, "s1", "test-sdk-safe-value-1")
	_, err = conjur.CreateStaticSecret(StaticSecret{Branch: safeBranch, Name: "s2", Value: "test-sdk-safe-value-2"})
	require.NoError(t, err, "create the secret s2")

	config := Config{}
	config.mergeEnv()
	reader, err := NewClientFromKey(config, authn.LoginPair{Login: "host/" + branch + "/wl-reader", APIKey: apiKey})
	require.NoError(t, err, "make a client for wl-reader")

	// s1 was made through the safe's route and s2 through /secrets/static.
	requireReads := func(step string, s1Readable bool) {
		t.Helper()
		value, err := reader.RetrieveSecret(safeBranch + "/s1")
		if s1Readable {
			require.NoError(t, err, "%s: read s1", step)
			assert.Equal(t, "test-sdk-safe-value-1", string(value), "%s: read s1", step)
		} else {
			requireSafeStatus(t, err, http.StatusNotFound, "", "%s: read s1", step)
		}
		_, err = reader.RetrieveSecret(safeBranch + "/s2")
		requireSafeStatus(t, err, http.StatusNotFound, "", "%s: read s2", step)
	}

	// The ticket asks that a grant on the safe lets the grantee read its
	// secrets. Today only membership in the safe's consumers group does, and
	// only for secrets made through the safe's route. This pins today's
	// behaviour; change it if the service does.
	requireReads("no grant", false)

	subject := Subject{Id: readers, Kind: "group"}
	grantSafePermission(t, conjur, safe, subject, []string{"read", "execute"})
	requireReads("granted read and execute on the safe", false)
	revokeSafePermission(t, conjur, safe, subject)

	consumers := safeBranch + "/delegation/consumers"
	consumer := GroupMember{ID: readers, Kind: "group"}
	_, err = conjur.AddGroupMember(consumers, consumer)
	require.NoError(t, err, "add readers to the safe's consumers")
	t.Cleanup(func() {
		_, err := conjur.RemoveGroupMember(consumers, consumer)
		ignoreSafeNotFound(t, err, "remove readers from the safe's consumers")
	})
	requireReads("in the safe's consumers", true)

	_, err = conjur.RemoveGroupMember(consumers, consumer)
	require.NoError(t, err, "remove readers from the safe's consumers")
	requireReads("removed from the safe's consumers", false)
}
