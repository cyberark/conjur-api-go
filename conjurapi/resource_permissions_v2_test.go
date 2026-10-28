package conjurapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permKindCase describes the route expectations for one kind.
type permKindCase struct {
	kind           PermissionKind
	identifier     string
	resourcePrefix string // URL prefix the permission routes hang off
	validPrivilege string // a privilege valid for this kind
	supportsUpdate bool   // whether a PUT (update-in-place) route exists
}

func resourcePermissionCases() []permKindCase {
	return []permKindCase{
		{
			kind:           PermissionKindWorkload,
			identifier:     "data/my-workload",
			resourcePrefix: "/workloads/data/my-workload/permissions",
			validPrivilege: "update",
			supportsUpdate: true,
		},
		{
			kind:           PermissionKindGroup,
			identifier:     "data/my-group",
			resourcePrefix: "/groups/data/my-group/permissions",
			validPrivilege: "update",
			supportsUpdate: false, // group has no PUT route
		},
		{
			kind:           PermissionKindBranch,
			identifier:     "data/my-branch",
			resourcePrefix: "/branches/data/my-branch/permissions",
			validPrivilege: "create", // valid only on branch
			supportsUpdate: true,
		},
	}
}

func TestResourcePermissions_PerKindGrantListRevoke(t *testing.T) {
	for _, tc := range resourcePermissionCases() {
		t.Run(string(tc.kind), func(t *testing.T) {
			ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == tc.resourcePrefix:
					w.WriteHeader(http.StatusCreated)
					w.Write([]byte(`{"subject":{"id":"data/ops","kind":"group"},"privileges":["` + tc.validPrivilege + `"]}`))
				case r.Method == http.MethodGet && r.URL.Path == tc.resourcePrefix:
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"permissions":[{"subject":{"id":"data/ops","kind":"group"},"privileges":["` + tc.validPrivilege + `"]}],"count":1}`))
				case r.Method == http.MethodDelete && r.URL.Path == tc.resourcePrefix+"/group/data/ops":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			defer ts.Close()

			target := PermissionTarget{Kind: tc.kind, Identifier: tc.identifier}
			subject := Subject{Id: "data/ops", Kind: "group"}

			perm, err := c.V2().GrantPermission(target, PermissionGrant{Subject: subject, Privileges: []string{tc.validPrivilege}})
			require.NoError(t, err, "grant on %s", tc.kind)
			assert.Equal(t, "data/ops", perm.Subject.Id)

			list, err := c.V2().ListPermissions(target, nil)
			require.NoError(t, err, "list on %s", tc.kind)
			assert.Equal(t, 1, list.Count)

			err = c.V2().RevokePermission(target, subject)
			require.NoError(t, err, "revoke on %s", tc.kind)
		})
	}
}

func TestResourcePermissions_PerKindUpdateSupport(t *testing.T) {
	c := newLocalPermClient("localhost")
	for _, tc := range resourcePermissionCases() {
		t.Run(string(tc.kind), func(t *testing.T) {
			_, err := c.UpdatePermission(
				PermissionTarget{Kind: tc.kind, Identifier: tc.identifier},
				PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{tc.validPrivilege}},
			)
			if tc.supportsUpdate {
				// Fails for lack of a server, not with the "not supported" guard.
				if err != nil {
					assert.NotContains(t, err.Error(), "not supported")
				}
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not supported")
			}
		})
	}
}

func TestResourcePermissions_PerKindErrorClassification(t *testing.T) {
	for _, tc := range resourcePermissionCases() {
		t.Run(string(tc.kind), func(t *testing.T) {
			tsC, cc := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"error":{"code":"conflict","message":"already"}}`))
			})
			defer tsC.Close()
			_, err := cc.V2().GrantPermission(
				PermissionTarget{Kind: tc.kind, Identifier: tc.identifier},
				PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{tc.validPrivilege}},
			)
			var conflictErr *response.ConjurError
			require.ErrorAs(t, err, &conflictErr, "%s grant conflict", tc.kind)
			assert.Equal(t, http.StatusConflict, conflictErr.Code, "%s grant conflict", tc.kind)

			tsR, cr := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				w.Write([]byte(`{"error":{"code":"unprocessable_entity","message":"Group 'data/ghost' not found in account 'conjur'"}}`))
			})
			defer tsR.Close()
			err = cr.V2().RevokePermission(
				PermissionTarget{Kind: tc.kind, Identifier: tc.identifier},
				Subject{Id: "data/ghost", Kind: "group"},
			)
			var roleErr *response.ConjurError
			require.ErrorAs(t, err, &roleErr, "%s revoke for a missing role", tc.kind)
			assert.Equal(t, http.StatusUnprocessableEntity, roleErr.Code, "%s revoke for a missing role", tc.kind)
		})
	}
}

func TestResourcePermissions_KindVocabularyRestriction(t *testing.T) {
	kinds := SupportedPermissionKinds()
	assert.Len(t, kinds, 4)
	assert.Contains(t, kinds, PermissionKindSafe)
	assert.NotContains(t, kinds, PermissionKind("authenticator"))

	c := newLocalPermClient("localhost")
	_, err := c.GrantPermission(
		PermissionTarget{Kind: PermissionKind("authenticator"), Identifier: "x"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
	)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "unsupported permission kind")
	// Error names the supported kinds so the caller can correct course.
	for _, k := range kinds {
		assert.Contains(t, msg, string(k))
	}
	assert.True(t, strings.Contains(msg, "workload"))
}
