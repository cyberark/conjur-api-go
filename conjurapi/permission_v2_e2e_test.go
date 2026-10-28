package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissionUpdatable says which kinds have an update route. Groups don't, so
// the SDK refuses UpdatePermission for them.
var permissionUpdatable = map[PermissionKind]bool{
	PermissionKindBranch:   true,
	PermissionKindGroup:    false,
	PermissionKindSafe:     true,
	PermissionKindWorkload: true,
}

// newTestPermissionClient returns a V2 client for the live tests, which run
// only on Secrets Manager SaaS.
func newTestPermissionClient(t *testing.T) *ClientV2 {
	t.Helper()
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	client := utils.Client()
	if !client.config.IsSaaS() {
		t.Skip("Skipping off Secrets Manager SaaS: permissions are SaaS-only")
	}
	return client.V2()
}

// newTestPermissionTargets creates a throwaway branch holding the groups
// target, grantee1, grantee2 and grantee3 and the workloads wl-target and
// wl-grantee, plus a static safe, and returns one target per kind. Everything
// is deleted when the test ends.
func newTestPermissionTargets(t *testing.T) (conjur *ClientV2, branch string, targets map[PermissionKind]PermissionTarget) {
	t.Helper()
	conjur = newTestPermissionClient(t)

	name := fmt.Sprintf("test-sdk-permission-%d", time.Now().UnixNano())
	_, err := conjur.CreateBranch(Branch{Branch: "data", Name: name})
	require.NoError(t, err, "create the test branch")
	branch = "data/" + name
	t.Cleanup(func() {
		err := conjur.DeleteBranch(branch)
		assertDeletedOrMissing(t, err, "delete the test branch")
	})

	for _, group := range []string{"target", "grantee1", "grantee2", "grantee3"} {
		_, err = conjur.CreateGroup(Group{Branch: branch, Name: group})
		require.NoError(t, err, "create the test group %s", group)
	}
	for _, workload := range []string{"wl-target", "wl-grantee"} {
		_, err = conjur.CreateWorkload(Workload{
			Branch:           branch,
			Name:             workload,
			AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
		})
		require.NoError(t, err, "create the test workload %s", workload)
	}
	createTestSafe(t, conjur, name)

	targets = map[PermissionKind]PermissionTarget{
		PermissionKindBranch:   {Kind: PermissionKindBranch, Identifier: branch},
		PermissionKindGroup:    {Kind: PermissionKindGroup, Identifier: branch + "/target"},
		PermissionKindSafe:     {Kind: PermissionKindSafe, Identifier: "static/" + name},
		PermissionKindWorkload: {Kind: PermissionKindWorkload, Identifier: branch + "/wl-target"},
	}
	for _, kind := range SupportedPermissionKinds() {
		require.Contains(t, targets, kind, "no test resource for this kind")
		require.Contains(t, permissionUpdatable, kind, "no update expectation for this kind")
	}
	return conjur, branch, targets
}

// createTestSafe creates a static safe and deletes it when the test ends. It
// sends the request itself because this branch has no CreateSafe; switch to
// CreateSafe and DeleteSafe once they land.
func createTestSafe(t *testing.T, conjur *ClientV2, name string) {
	t.Helper()
	// Registered before the create, so a create that fails after the safe
	// was made still cleans up. Safes don't live under the test branch.
	t.Cleanup(func() { deleteTestSafe(t, conjur, name) })

	req, err := newV2JSONRequest(
		http.MethodPost,
		makeRouterURL(conjur.config.ApplianceURL, "safes").String(),
		map[string]string{"type": "static", "name": name},
		v2APIHeaderBeta,
	)
	require.NoError(t, err)
	_, err = submitAndReadData(conjur, req)
	require.NoError(t, err, "create the test safe static/%s", name)
}

func deleteTestSafe(t *testing.T, conjur *ClientV2, name string) {
	t.Helper()
	req, err := newV2Request(
		http.MethodDelete,
		makeRouterURL(conjur.config.ApplianceURL, "safes", "static", name).String(),
		v2APIHeaderBeta,
	)
	require.NoError(t, err)
	assertDeletedOrMissing(t, submitAndEmpty(conjur, req), "delete the test safe static/%s", name)
}

// assertDeletedOrMissing accepts a cleanup delete that worked or found
// nothing to delete.
func assertDeletedOrMissing(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	var conjurErr *response.ConjurError
	if !errors.As(err, &conjurErr) || conjurErr.Code != http.StatusNotFound {
		assert.NoError(t, err, msgAndArgs...)
	}
}

// requirePermissionStatus requires err to be a *response.ConjurError with the
// given HTTP status, and returns it.
func requirePermissionStatus(t *testing.T, err error, code int, msgAndArgs ...any) *response.ConjurError {
	t.Helper()
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr, msgAndArgs...)
	require.Equal(t, code, conjurErr.Code, msgAndArgs...)
	return conjurErr
}

// findPermission returns the subject's entry in list, or nil.
func findPermission(list *PermissionResponse, subject Subject) *Permission {
	for i, p := range list.Permission {
		if p.Subject == subject {
			return &list.Permission[i]
		}
	}
	return nil
}

func TestClientV2_Permissions_GrantListRevoke(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	grantee := Subject{Id: branch + "/grantee1", Kind: "group"}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			// A new safe already has the grants the service gives its own
			// groups, so the counts are relative to what is there.
			before, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)

			perm, err := conjur.GrantPermission(target, PermissionGrant{Subject: grantee, Privileges: []string{"read"}})
			require.NoError(t, err)
			assert.Equal(t, grantee, perm.Subject)
			assert.Equal(t, []string{"read"}, perm.Privileges)

			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.Equal(t, before.Count+1, list.Count)
			listed := findPermission(list, grantee)
			require.NotNil(t, listed, "the grant is listed")
			assert.Equal(t, []string{"read"}, listed.Privileges)

			require.NoError(t, conjur.RevokePermission(target, grantee))
			list, err = conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.Equal(t, before.Count, list.Count)
			assert.Nil(t, findPermission(list, grantee), "the grant is gone")

			// The tickets ask for an error when the grant doesn't exist, but
			// the service answers 204 for a grant that is already gone or was
			// never made. This pins today's behaviour; change it if the
			// service starts refusing.
			assert.NoError(t, conjur.RevokePermission(target, grantee), "revoke again")
			assert.NoError(t, conjur.RevokePermission(target, Subject{Id: branch + "/grantee2", Kind: "group"}), "revoke a grant never made")
		})
	}
}

func TestClientV2_Permissions_DuplicateGrantConflicts(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	grantee := Subject{Id: branch + "/grantee1", Kind: "group"}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			_, err := conjur.GrantPermission(target, PermissionGrant{Subject: grantee, Privileges: []string{"read"}})
			require.NoError(t, err)

			for _, privileges := range [][]string{{"read"}, {"read", "update"}} {
				_, err = conjur.GrantPermission(target, PermissionGrant{Subject: grantee, Privileges: privileges})
				conjurErr := requirePermissionStatus(t, err, http.StatusConflict, "grant %v again", privileges)
				require.NotNil(t, conjurErr.Details)
				assert.Equal(t, "conflict", conjurErr.Details.Code)
			}

			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			listed := findPermission(list, grantee)
			require.NotNil(t, listed)
			assert.Equal(t, []string{"read"}, listed.Privileges, "the first grant is unchanged")
		})
	}
}

func TestClientV2_Permissions_Update(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	grantee := Subject{Id: branch + "/grantee1", Kind: "group"}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			_, err := conjur.GrantPermission(target, PermissionGrant{Subject: grantee, Privileges: []string{"read"}})
			require.NoError(t, err)

			if !permissionUpdatable[kind] {
				_, err := conjur.UpdatePermission(target, PermissionGrant{Subject: grantee, Privileges: []string{"read", "update"}})
				require.Error(t, err)
				var conjurErr *response.ConjurError
				assert.False(t, errors.As(err, &conjurErr), "refused by the SDK, not the service: %v", err)

				list, err := conjur.ListPermissions(target, nil)
				require.NoError(t, err)
				listed := findPermission(list, grantee)
				require.NotNil(t, listed)
				assert.Equal(t, []string{"read"}, listed.Privileges)
				return
			}

			// Each update replaces the subject's privileges; the last one
			// drops read, so nothing is merged.
			for _, privileges := range [][]string{{"read", "update"}, {"update"}} {
				perm, err := conjur.UpdatePermission(target, PermissionGrant{Subject: grantee, Privileges: privileges})
				require.NoError(t, err, "update to %v", privileges)
				assert.ElementsMatch(t, privileges, perm.Privileges)

				list, err := conjur.ListPermissions(target, nil)
				require.NoError(t, err)
				listed := findPermission(list, grantee)
				require.NotNil(t, listed)
				assert.ElementsMatch(t, privileges, listed.Privileges, "listed after the update to %v", privileges)
			}

			// The service creates the grant when the subject has none.
			newcomer := Subject{Id: branch + "/grantee3", Kind: "group"}
			perm, err := conjur.UpdatePermission(target, PermissionGrant{Subject: newcomer, Privileges: []string{"read"}})
			require.NoError(t, err)
			assert.Equal(t, []string{"read"}, perm.Privileges)
			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.NotNil(t, findPermission(list, newcomer), "the update made a grant")
		})
	}
}

func TestClientV2_Permissions_MissingRole(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	missing := Subject{Id: branch + "/no-such-group", Kind: "group"}
	grant := PermissionGrant{Subject: missing, Privileges: []string{"read"}}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			// A missing role gets the same 422 as a validation error, so only
			// the message tells them apart.
			requireRoleNotFound := func(err error, op string) {
				t.Helper()
				conjurErr := requirePermissionStatus(t, err, http.StatusUnprocessableEntity, op)
				assert.Contains(t, conjurErr.Error(), "'"+missing.Id+"' not found", op)
			}

			_, err := conjur.GrantPermission(target, grant)
			requireRoleNotFound(err, "grant")
			if permissionUpdatable[kind] {
				_, err = conjur.UpdatePermission(target, grant)
				requireRoleNotFound(err, "update")
			}
			requireRoleNotFound(conjur.RevokePermission(target, missing), "revoke")
		})
	}
}

func TestClientV2_Permissions_MissingResource(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	grantee := Subject{Id: branch + "/grantee1", Kind: "group"}
	grant := PermissionGrant{Subject: grantee, Privileges: []string{"read"}}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			target.Identifier += "-missing"

			_, err := conjur.ListPermissions(target, nil)
			requirePermissionStatus(t, err, http.StatusNotFound, "list")
			_, err = conjur.GrantPermission(target, grant)
			requirePermissionStatus(t, err, http.StatusNotFound, "grant")
			if permissionUpdatable[kind] {
				_, err = conjur.UpdatePermission(target, grant)
				requirePermissionStatus(t, err, http.StatusNotFound, "update")
			}
			requirePermissionStatus(t, conjur.RevokePermission(target, grantee), http.StatusNotFound, "revoke")
		})
	}
}

func TestClientV2_Permissions_ProtectedBranch(t *testing.T) {
	conjur := newTestPermissionClient(t)
	target := PermissionTarget{Kind: PermissionKindBranch, Identifier: "data"}
	// The role doesn't exist, so nothing can be written on data even if the
	// service stops protecting it.
	missing := Subject{Id: fmt.Sprintf("data/test-sdk-permission-%d/no-such-group", time.Now().UnixNano()), Kind: "group"}

	_, err := conjur.GrantPermission(target, PermissionGrant{Subject: missing, Privileges: []string{"read"}})
	requirePermissionStatus(t, err, http.StatusForbidden, "grant")
	requirePermissionStatus(t, conjur.RevokePermission(target, missing), http.StatusForbidden, "revoke")
}

func TestClientV2_Permissions_PrivilegesPerKind(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	// The SDK doesn't export these; they are what the service allows today.
	allowed := map[PermissionKind][]string{
		PermissionKindBranch:   {"read", "update", "create"},
		PermissionKindGroup:    {"read", "update"},
		PermissionKindSafe:     {"read", "update", "create", "execute"},
		PermissionKindWorkload: {"read", "update"},
	}
	// Every privilege the service knows of, for any kind.
	known := []string{"read", "execute", "update", "create", "delete", "authenticate", "use"}
	grantee := Subject{Id: branch + "/grantee1", Kind: "group"}
	refused := Subject{Id: branch + "/grantee2", Kind: "group"}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			require.Contains(t, allowed, kind, "no privilege list for this kind")
			target := targets[kind]

			perm, err := conjur.GrantPermission(target, PermissionGrant{Subject: grantee, Privileges: allowed[kind]})
			require.NoError(t, err, "grant every allowed privilege")
			assert.ElementsMatch(t, allowed[kind], perm.Privileges)

			requireNotAllowed := func(err error, privilege, op string) {
				t.Helper()
				conjurErr := requirePermissionStatus(t, err, http.StatusUnprocessableEntity, "%s %s", op, privilege)
				msg := conjurErr.Details.Message
				assert.Contains(t, msg, "Privilege '"+privilege+"' is not allowed", op)
				_, list, found := strings.Cut(msg, "Allowed privileges are: ")
				require.True(t, found, "the message lists the allowed privileges: %s", msg)
				assert.ElementsMatch(t, allowed[kind], strings.Split(strings.TrimSuffix(list, "."), ", "), op)
			}
			for _, privilege := range known {
				if contains(allowed[kind], privilege) {
					continue
				}
				_, err := conjur.GrantPermission(target, PermissionGrant{Subject: refused, Privileges: []string{privilege}})
				requireNotAllowed(err, privilege, "grant")
				if permissionUpdatable[kind] {
					_, err = conjur.UpdatePermission(target, PermissionGrant{Subject: grantee, Privileges: []string{privilege}})
					requireNotAllowed(err, privilege, "update")
				}
			}

			_, err = conjur.GrantPermission(target, PermissionGrant{Subject: refused, Privileges: []string{"bogus"}})
			requirePermissionStatus(t, err, http.StatusUnprocessableEntity, "grant bogus")

			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.Nil(t, findPermission(list, refused), "no refused grant was made")
			listed := findPermission(list, grantee)
			require.NotNil(t, listed)
			assert.ElementsMatch(t, allowed[kind], listed.Privileges, "refused updates changed nothing")
		})
	}
}

func TestClientV2_Permissions_GranteeKinds(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	// The subject kinds the service accepts on each kind today.
	allowed := map[PermissionKind][]string{
		PermissionKindBranch:   {"group"},
		PermissionKindGroup:    {"group"},
		PermissionKindSafe:     {"group", "user", "edge", "cp"},
		PermissionKindWorkload: {"group"},
	}
	workload := Subject{Id: branch + "/wl-grantee", Kind: "workload"}

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			require.Contains(t, allowed, kind, "no grantee kinds for this kind")
			target := targets[kind]

			_, err := conjur.GrantPermission(target, PermissionGrant{Subject: workload, Privileges: []string{"read"}})
			conjurErr := requirePermissionStatus(t, err, http.StatusUnprocessableEntity)
			for _, grantee := range allowed[kind] {
				assert.Contains(t, conjurErr.Details.Message, "'"+grantee+"'")
			}

			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.Nil(t, findPermission(list, workload))
		})
	}
}

func TestClientV2_Permissions_ListPaging(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)

	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := targets[kind]
			before, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			for _, group := range []string{"grantee1", "grantee2", "grantee3"} {
				_, err := conjur.GrantPermission(target, PermissionGrant{
					Subject:    Subject{Id: branch + "/" + group, Kind: "group"},
					Privileges: []string{"read"},
				})
				require.NoError(t, err)
			}
			all, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			require.Equal(t, before.Count+3, all.Count)
			var want []string
			for _, p := range all.Permission {
				want = append(want, p.Subject.Id)
			}

			var got []string
			filter := &PermissionFilter{Limit: 2}
			for page := 0; ; page++ {
				require.Less(t, page, 10, "paging didn't end")
				resp, err := conjur.ListPermissions(target, filter)
				require.NoError(t, err)
				assert.Equal(t, all.Count, resp.Count, "count on page %d", page)
				assert.LessOrEqual(t, len(resp.Permission), filter.Limit)
				for _, p := range resp.Permission {
					got = append(got, p.Subject.Id)
				}
				if filter.Offset+len(resp.Permission) >= resp.Count {
					break
				}
				filter = &PermissionFilter{Limit: 2, Offset: filter.Offset + len(resp.Permission)}
			}
			assert.ElementsMatch(t, want, got, "the pages hold every grant once")

			past := &PermissionFilter{Limit: 2, Offset: all.Count + 5}
			resp, err := conjur.ListPermissions(target, past)
			require.NoError(t, err)
			assert.Empty(t, resp.Permission)
			assert.Equal(t, all.Count, resp.Count)

			_, err = conjur.ListPermissions(target, &PermissionFilter{Limit: 1001})
			requirePermissionStatus(t, err, http.StatusUnprocessableEntity, "limit over 1000")
		})
	}
}

// A grant made by policy to a policy role is listed with the subject kind
// "branch", but the revoke route accepts only "policy" for it.
func TestClientV2_Permissions_PolicyGrant(t *testing.T) {
	conjur, branch, targets := newTestPermissionTargets(t)
	policy := `
- !policy
  id: grantee-policy
- !policy
  id: target-branch
- !permit
  role: !policy grantee-policy
  privileges: [ read ]
  resources:
  - !group target
  - !host wl-target
  - !policy target-branch
`
	_, err := conjur.LoadPolicy(PolicyModePost, branch, strings.NewReader(policy))
	require.NoError(t, err)
	// Safes are left out: their permissions aren't granted from a branch
	// policy.
	policyTargets := map[PermissionKind]PermissionTarget{
		PermissionKindBranch:   {Kind: PermissionKindBranch, Identifier: branch + "/target-branch"},
		PermissionKindGroup:    targets[PermissionKindGroup],
		PermissionKindWorkload: targets[PermissionKindWorkload],
	}
	listedSubject := Subject{Id: branch + "/grantee-policy", Kind: "branch"}

	for _, kind := range []PermissionKind{PermissionKindBranch, PermissionKindGroup, PermissionKindWorkload} {
		t.Run(string(kind), func(t *testing.T) {
			target := policyTargets[kind]
			list, err := conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			listed := findPermission(list, listedSubject)
			require.NotNil(t, listed, "the policy grant is listed with kind branch: %+v", list.Permission)
			assert.Equal(t, []string{"read"}, listed.Privileges)

			// Revoking what the list shows fails today. Change this if the
			// service starts accepting "branch" here.
			err = conjur.RevokePermission(target, listed.Subject)
			requirePermissionStatus(t, err, http.StatusUnprocessableEntity, "revoke with the listed kind")
			list, err = conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.NotNil(t, findPermission(list, listedSubject), "the grant is still there")

			require.NoError(t, conjur.RevokePermission(target, Subject{Id: listedSubject.Id, Kind: "policy"}))
			list, err = conjur.ListPermissions(target, nil)
			require.NoError(t, err)
			assert.Nil(t, findPermission(list, listedSubject), "the grant is gone")
		})
	}
}
