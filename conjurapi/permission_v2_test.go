package conjurapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLocalPermClient(applianceURL string) *ClientV2 {
	return &ClientV2{Client: &Client{config: Config{
		ApplianceURL: applianceURL,
		Account:      "myTestAccount",
		Environment:  EnvironmentSaaS,
	}}}
}

func newSaaSPermServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
	})
	mux.HandleFunc("/", handler)

	ts := httptest.NewServer(mux)
	client, err := NewClientFromJwt(Config{
		ApplianceURL:      ts.URL,
		Account:           "myTestAccount",
		AuthnType:         "jwt",
		ServiceID:         "jwt_service",
		JWTContent:        `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:       EnvironmentSaaS,
		CredentialStorage: CredentialStorageNone,
	})
	if err != nil {
		ts.Close()
		t.Fatalf("NewClientFromJwt: %s", err)
	}
	return ts, client
}

func TestSupportedPermissionKinds(t *testing.T) {
	assert.Equal(t, []PermissionKind{PermissionKindBranch, PermissionKindGroup, PermissionKindSafe, PermissionKindWorkload}, SupportedPermissionKinds())
	assert.Equal(t, []string{"branch", "group", "safe", "workload"}, SupportedPermissionKindNames())
}

func TestPermissionIdentifier_RejectsTraversal(t *testing.T) {
	c := newLocalPermClient("localhost")

	for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
		_, err := c.GrantPermissionRequest(
			PermissionTarget{Kind: PermissionKindBranch, Identifier: bad},
			PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
		)
		assert.Errorf(t, err, "resource identifier %q must be rejected", bad)

		_, err = c.RevokePermissionRequest(
			PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"},
			Subject{Id: bad, Kind: "group"},
		)
		assert.Errorf(t, err, "role id %q must be rejected", bad)
	}
}

func TestGrantPermissionRequest_PerKindURL(t *testing.T) {
	c := newLocalPermClient("localhost")
	grant := PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}}

	testCases := []struct {
		kind PermissionKind
		id   string
		path string
	}{
		{PermissionKindWorkload, "data/my-workload", "localhost/workloads/data/my-workload/permissions"},
		{PermissionKindGroup, "data/my-group", "localhost/groups/data/my-group/permissions"},
		{PermissionKindBranch, "data/my-branch", "localhost/branches/data/my-branch/permissions"},
		{PermissionKindSafe, "managed/MySafe", "localhost/safes/managed/MySafe/permissions"},
	}
	for _, tc := range testCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			req, err := c.GrantPermissionRequest(PermissionTarget{Kind: tc.kind, Identifier: tc.id}, grant)
			require.NoError(t, err)
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, tc.path, req.URL.Path)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))

			body, _ := io.ReadAll(req.Body)
			var sent grantBody
			require.NoError(t, json.Unmarshal(body, &sent))
			assert.Equal(t, "data/ops", sent.Subject.Id)
			assert.Equal(t, []string{"read"}, sent.Privileges)
		})
	}
}

func TestRevokeAndUpdatePermissionRequest_RoleSegments(t *testing.T) {
	c := newLocalPermClient("localhost")
	subject := Subject{Id: "data/ops team", Kind: "group"}

	revoke, err := c.RevokePermissionRequest(PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"}, subject)
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, revoke.Method)
	// role id keeps its slashes (route *role_id glob) but the space is escaped.
	assert.Equal(t, "localhost/branches/data/b/permissions/group/data/ops%20team", revoke.URL.EscapedPath())

	upd, err := c.UpdatePermissionRequest(
		PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"},
		PermissionGrant{Subject: subject, Privileges: []string{"read", "update"}},
	)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, upd.Method)
	body, _ := io.ReadAll(upd.Body)
	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &sent))
	// PUT sends only privileges.
	assert.Contains(t, sent, "privileges")
	assert.NotContains(t, sent, "subject")
}

func TestListPermissionsRequest_Pagination(t *testing.T) {
	c := newLocalPermClient("localhost")
	req, err := c.ListPermissionsRequest(PermissionTarget{Kind: PermissionKindWorkload, Identifier: "data/w"}, &PermissionFilter{Limit: 10, Offset: 20})
	require.NoError(t, err)
	assert.Equal(t, "localhost/workloads/data/w/permissions", req.URL.Path)
	assert.Equal(t, "limit=10&offset=20", req.URL.RawQuery)
}

// The service validates privileges and grantee kinds, so the SDK sends them as
// given and returns the service's rejection unchanged.
func TestGrantPermission_LeavesValidationToTheService(t *testing.T) {
	c := newLocalPermClient("localhost")
	for _, grant := range []PermissionGrant{
		{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"create"}},
		{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"bogus"}},
		{Subject: Subject{Id: "alice", Kind: "user"}, Privileges: []string{"read"}},
		{Subject: Subject{Id: "x", Kind: "bogus"}, Privileges: []string{"read"}},
	} {
		_, err := c.GrantPermissionRequest(PermissionTarget{Kind: PermissionKindWorkload, Identifier: "data/w"}, grant)
		assert.NoError(t, err, "%+v must reach the service", grant)
	}

	const reason = "Privilege 'create' is not allowed. Allowed privileges are: read, update"
	ts, sc := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":{"code":"unprocessable_entity","message":"` + reason + `"}}`))
	})
	defer ts.Close()

	_, err := sc.V2().GrantPermission(
		PermissionTarget{Kind: PermissionKindWorkload, Identifier: "data/w"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"create"}},
	)
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
	assert.EqualError(t, err, "422 Unprocessable Entity. "+reason+".")
}

func TestGrantPermission_RequiresSubjectAndPrivileges(t *testing.T) {
	c := newLocalPermClient("localhost")

	_, err := c.GrantPermission(PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"}, PermissionGrant{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject id and kind")
	assert.Contains(t, err.Error(), "at least one privilege")

	// An unknown kind has no route, so it is rejected before any request.
	_, err = c.GrantPermission(
		PermissionTarget{Kind: PermissionKind("nope"), Identifier: "x"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
	)
	assert.ErrorContains(t, err, "unsupported permission kind")
}

func TestUpdatePermission_UnsupportedForGroup(t *testing.T) {
	c := newLocalPermClient("localhost")
	_, err := c.UpdatePermission(
		PermissionTarget{Kind: PermissionKindGroup, Identifier: "data/g"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	// The request builder refuses it too.
	_, err = c.UpdatePermissionRequest(
		PermissionTarget{Kind: PermissionKindGroup, Identifier: "data/g"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
	)
	assert.ErrorContains(t, err, "not supported")
}

func TestPermissionExecutors_GrantListRevoke(t *testing.T) {
	ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/branches/data/b/permissions":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"subject":{"id":"data/ops","kind":"group"},"privileges":["read","update"]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/branches/data/b/permissions":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"permissions":[{"subject":{"id":"data/ops","kind":"group"},"privileges":["read"]}],"count":1}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/branches/data/b/permissions/group/data/ops":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	defer ts.Close()

	target := PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"}

	perm, err := c.V2().GrantPermission(target, PermissionGrant{
		Subject:    Subject{Id: "data/ops", Kind: "group"},
		Privileges: []string{"read", "update"},
	})
	require.NoError(t, err)
	assert.Equal(t, "data/ops", perm.Subject.Id)
	assert.ElementsMatch(t, []string{"read", "update"}, perm.Privileges)

	list, err := c.V2().ListPermissions(target, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, list.Count)
	require.Len(t, list.Permission, 1)
	assert.Equal(t, "data/ops", list.Permission[0].Subject.Id)

	err = c.V2().RevokePermission(target, Subject{Id: "data/ops", Kind: "group"})
	require.NoError(t, err)
}

func TestGrantPermission_DuplicateConflicts(t *testing.T) {
	ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"conflict","message":"The subject already has permissions on this branch. Delete or update the existing permissions"}}`))
	})
	defer ts.Close()

	_, err := c.V2().GrantPermission(
		PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"},
		PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}},
	)
	var conflictErr *response.ConjurError
	require.ErrorAs(t, err, &conflictErr, "duplicate grant must surface a *response.ConjurError")
	assert.Equal(t, http.StatusConflict, conflictErr.Code, "duplicate grant must be classifiable as a conflict")
}

// Revoking a grant that doesn't exist gets 204 from the service, so only a
// missing resource or a missing role comes back as an error.
func TestRevokePermission_MissingResourceNotFound(t *testing.T) {
	ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"Branch 'data/b' not found in account 'conjur'"}}`))
	})
	defer ts.Close()

	err := c.V2().RevokePermission(
		PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"},
		Subject{Id: "data/ops", Kind: "group"},
	)
	var notFoundErr *response.ConjurError
	require.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, http.StatusNotFound, notFoundErr.Code)
}

func TestRevokePermission_MissingRoleUnprocessable(t *testing.T) {
	ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":{"code":"unprocessable_entity","message":"Group 'data/ghost' not found in account 'conjur'"}}`))
	})
	defer ts.Close()

	err := c.V2().RevokePermission(
		PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"},
		Subject{Id: "data/ghost", Kind: "group"},
	)
	var roleErr *response.ConjurError
	require.ErrorAs(t, err, &roleErr)
	assert.Equal(t, http.StatusUnprocessableEntity, roleErr.Code)
	assert.Contains(t, roleErr.Error(), "Group 'data/ghost' not found")
}

// Self-Hosted has no permission routes, so every kind, branch included, is
// refused before a request is sent, by the methods and the request builders.
func TestPermissions_SaaSOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
	})
	for _, prefix := range []string{"/branches/", "/groups/", "/workloads/", "/safes/"} {
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		})
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, err := NewClientFromJwt(Config{
		ApplianceURL:      ts.URL,
		Account:           "myTestAccount",
		AuthnType:         "jwt",
		ServiceID:         "jwt_service",
		JWTContent:        `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:       EnvironmentSH,
		CredentialStorage: CredentialStorageNone,
	})
	require.NoError(t, err)

	subject := Subject{Id: "data/ops", Kind: "group"}
	grant := PermissionGrant{Subject: subject, Privileges: []string{"read"}}
	for _, kind := range SupportedPermissionKinds() {
		t.Run(string(kind), func(t *testing.T) {
			target := PermissionTarget{Kind: kind, Identifier: "data/x"}
			_, grantErr := client.V2().GrantPermission(target, grant)
			_, updateErr := client.V2().UpdatePermission(target, grant)
			revokeErr := client.V2().RevokePermission(target, subject)
			_, listErr := client.V2().ListPermissions(target, nil)
			_, grantReqErr := client.V2().GrantPermissionRequest(target, grant)
			_, updateReqErr := client.V2().UpdatePermissionRequest(target, grant)
			_, revokeReqErr := client.V2().RevokePermissionRequest(target, subject)
			_, listReqErr := client.V2().ListPermissionsRequest(target, nil)

			for _, err := range []error{grantErr, updateErr, revokeErr, listErr, grantReqErr, updateReqErr, revokeReqErr, listReqErr} {
				var notSupported *contract.FeatureNotSupportedError
				require.ErrorAs(t, err, &notSupported)
				assert.Equal(t, string(contract.CapabilityPermissionsV2), notSupported.FeatureName)
			}
		})
	}
}

// The role kind goes into the URL on revoke and update, so it is escaped as one
// segment and may not be empty, "." or "..".
func TestPermissionRoleKind_IsOneSegment(t *testing.T) {
	c := newLocalPermClient("localhost")
	target := PermissionTarget{Kind: PermissionKindBranch, Identifier: "data/b"}

	for _, bad := range []string{"", ".", ".."} {
		_, err := c.RevokePermissionRequest(target, Subject{Id: "data/ops", Kind: bad})
		assert.Errorf(t, err, "role kind %q must be rejected", bad)
		_, err = c.UpdatePermissionRequest(target, PermissionGrant{Subject: Subject{Id: "data/ops", Kind: bad}, Privileges: []string{"read"}})
		assert.Errorf(t, err, "role kind %q must be rejected", bad)
	}

	req, err := c.RevokePermissionRequest(target, Subject{Id: "data/ops", Kind: "a/b"})
	require.NoError(t, err)
	assert.Contains(t, req.URL.EscapedPath(), "/permissions/a%2Fb/data/ops")
}

func TestSafePermissionRequests(t *testing.T) {
	c := newLocalPermClient("localhost")
	target := PermissionTarget{Kind: PermissionKindSafe, Identifier: "managed/team/My Safe"}
	subject := Subject{Id: "data/ops", Kind: "group"}

	list, err := c.ListPermissionsRequest(target, &PermissionFilter{Limit: 10, Offset: 20})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, list.Method)
	assert.Equal(t, "localhost/safes/managed/team/My%20Safe/permissions", list.URL.EscapedPath())
	assert.Equal(t, "10", list.URL.Query().Get("limit"))
	assert.Equal(t, "20", list.URL.Query().Get("offset"))

	revoke, err := c.RevokePermissionRequest(target, subject)
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, revoke.Method)
	assert.Equal(t, "localhost/safes/managed/team/My%20Safe/permissions/group/data/ops", revoke.URL.EscapedPath())

	upd, err := c.UpdatePermissionRequest(target, PermissionGrant{Subject: subject, Privileges: []string{"read", "execute"}})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPatch, upd.Method, "a safe grant is updated with PATCH")
	assert.Equal(t, "localhost/safes/managed/team/My%20Safe/permissions/group/data/ops", upd.URL.EscapedPath())
	body, _ := io.ReadAll(upd.Body)
	assert.JSONEq(t, `{"privileges":["read","execute"]}`, string(body))
}

func TestUpdatePermissionRequest_MethodPerKind(t *testing.T) {
	c := newLocalPermClient("localhost")
	grant := PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}}

	for kind, method := range map[PermissionKind]string{
		PermissionKindBranch:   http.MethodPut,
		PermissionKindWorkload: http.MethodPut,
		PermissionKindSafe:     http.MethodPatch,
	} {
		id := "data/x"
		if kind == PermissionKindSafe {
			id = "managed/x"
		}
		req, err := c.UpdatePermissionRequest(PermissionTarget{Kind: kind, Identifier: id}, grant)
		require.NoError(t, err)
		assert.Equal(t, method, req.Method, "kind %s", kind)
	}
}

func TestSafePermissionIdentifier(t *testing.T) {
	c := newLocalPermClient("localhost")
	grant := PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}}

	_, err := c.GrantPermissionRequest(PermissionTarget{Kind: PermissionKindSafe, Identifier: "MySafe"}, grant)
	assert.ErrorContains(t, err, "<type>/<name>")

	for _, bad := range []string{"managed/../x", "../MySafe", "managed//x", "managed/"} {
		_, err := c.GrantPermissionRequest(PermissionTarget{Kind: PermissionKindSafe, Identifier: bad}, grant)
		assert.Errorf(t, err, "safe identifier %q must be rejected", bad)
	}
}

func TestGrantPermission_SafeGrantees(t *testing.T) {
	c := newLocalPermClient("localhost")
	target := PermissionTarget{Kind: PermissionKindSafe, Identifier: "managed/MySafe"}

	for _, kind := range []string{"group", "user", "edge", "cp", "workload"} {
		_, err := c.GrantPermissionRequest(target, PermissionGrant{Subject: Subject{Id: "x", Kind: kind}, Privileges: []string{"execute"}})
		assert.NoError(t, err, "%s is left for the service to accept or reject", kind)
	}
}

func TestSafePermissionExecutors(t *testing.T) {
	ts, c := newSaaSPermServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/safes/managed/MySafe/permissions":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"subject":{"id":"ops","kind":"user"},"privileges":["read"]}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/safes/managed/MySafe/permissions/user/ops":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"subject":{"id":"ops","kind":"user"},"privileges":["read","execute"]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/safes/managed/MySafe/permissions":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"permissions":[{"subject":{"id":"ops","kind":"user"},"privileges":["read","execute"]}],"count":1}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/safes/managed/MySafe/permissions/user/ops":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	defer ts.Close()

	target := PermissionTarget{Kind: PermissionKindSafe, Identifier: "managed/MySafe"}
	subject := Subject{Id: "ops", Kind: "user"}

	perm, err := c.V2().GrantPermission(target, PermissionGrant{Subject: subject, Privileges: []string{"read"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"read"}, perm.Privileges)

	perm, err = c.V2().UpdatePermission(target, PermissionGrant{Subject: subject, Privileges: []string{"read", "execute"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"read", "execute"}, perm.Privileges)

	list, err := c.V2().ListPermissions(target, nil)
	require.NoError(t, err)
	require.Len(t, list.Permission, 1)
	assert.Equal(t, "ops", list.Permission[0].Subject.Id)

	require.NoError(t, c.V2().RevokePermission(target, subject))
}

func TestPermissions_ValidationErrorWithDetailsList(t *testing.T) {
	ts, client := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(validationFailedBody))
	})
	defer ts.Close()
	c := client.V2()
	want := "422 Unprocessable Entity. value is not present."
	target := PermissionTarget{Kind: PermissionKindGroup, Identifier: "data/g"}
	grant := PermissionGrant{Subject: Subject{Id: "data/ops", Kind: "group"}, Privileges: []string{"read"}}

	_, err := c.GrantPermission(target, grant)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	_, err = c.ListPermissions(target, nil)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	err = c.RevokePermission(target, grant.Subject)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())
}
