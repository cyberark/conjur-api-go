package conjurapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newSaaSGroupServer wraps a resource handler with the JWT authenticate
// endpoint and /info, returning a SaaS-configured authenticated client. Mirrors
// the workload test helper so the group executor methods (which call
// SubmitRequest) can run under httptest.
func newSaaSGroupServer(t *testing.T, resourceHandler http.HandlerFunc) (*httptest.Server, *Client) {
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
	mux.HandleFunc("/", resourceHandler)

	ts := httptest.NewServer(mux)
	config := Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSaaS,
	}
	client, err := NewClientFromJwt(config)
	if err != nil {
		ts.Close()
		t.Fatalf("NewClientFromJwt: %s", err)
	}
	return ts, client
}

func newLocalGroupClient(applianceURL string) *ClientV2 {
	return &ClientV2{Client: &Client{config: Config{
		ApplianceURL: applianceURL,
		Account:      "myTestAccount",
		Environment:  EnvironmentSaaS,
	}}}
}

func TestGroupValidate(t *testing.T) {
	err := Group{}.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Branch")
	assert.Contains(t, err.Error(), "Name")

	assert.NoError(t, Group{Name: "g", Branch: "data"}.Validate())
}

func TestGroupIdentifier(t *testing.T) {
	assert.Equal(t, "data/my-group", Group{Name: "my-group", Branch: "data"}.identifier())
	// Empty Branch: Name is assumed to already be a full identifier.
	assert.Equal(t, "data/my-group", Group{Name: "data/my-group"}.identifier())
}

func TestCreateGroupRequest_OnlyPermittedFields(t *testing.T) {
	c := newLocalGroupClient("localhost")

	_, err := c.CreateGroupRequest(Group{})
	assert.Error(t, err)

	req, err := c.CreateGroupRequest(Group{
		Name:        "my-group",
		Branch:      "data",
		Annotations: map[string]string{"team": "witchers"},
	})
	assert.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "localhost/groups", req.URL.Path) // SaaS: no account segment
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))

	body, _ := io.ReadAll(req.Body)
	var sent map[string]interface{}
	assert.NoError(t, json.Unmarshal(body, &sent))
	assert.Equal(t, "my-group", sent["name"])
	assert.Equal(t, "data", sent["branch"])
	assert.Contains(t, sent, "annotations")
	// v2 has no owner field on groups — it must never be sent.
	_, hasOwner := sent["owner"]
	assert.False(t, hasOwner, "v2 group create must not send owner")
}

func TestReadGroupsRequest_Pagination(t *testing.T) {
	c := newLocalGroupClient("localhost")

	req, err := c.ReadGroupsRequest(nil)
	assert.NoError(t, err)
	assert.Equal(t, "localhost/groups", req.URL.Path)
	assert.Equal(t, "", req.URL.RawQuery)

	req, err = c.ReadGroupsRequest(&GroupFilter{Limit: 20, Offset: 40})
	assert.NoError(t, err)
	assert.Equal(t, "limit=20&offset=40", req.URL.RawQuery)
}

func TestUpdateGroupRequest_OnlyAnnotations(t *testing.T) {
	c := newLocalGroupClient("localhost")

	req, err := c.UpdateGroupRequest("data/my-group", map[string]string{"team": "witchers"})
	assert.NoError(t, err)
	assert.Equal(t, http.MethodPatch, req.Method)
	assert.Equal(t, "localhost/groups/data/my-group", req.URL.Path)

	body, _ := io.ReadAll(req.Body)
	var sent map[string]interface{}
	assert.NoError(t, json.Unmarshal(body, &sent))
	assert.Contains(t, sent, "annotations")
	assert.Len(t, sent, 1, "update must send only annotations")

	_, err = c.UpdateGroupRequest("", nil)
	assert.Error(t, err)
}

func TestGroupsResponse_HasMore(t *testing.T) {
	page := func(n int) []Group { return make([]Group, n) }
	assert.True(t, GroupsResponse{Groups: page(10), Count: 25}.HasMore(&GroupFilter{Limit: 10, Offset: 0}))
	assert.False(t, GroupsResponse{Groups: page(5), Count: 25}.HasMore(&GroupFilter{Limit: 10, Offset: 20}))
	assert.False(t, GroupsResponse{Groups: page(3), Count: 3}.HasMore(nil))
}

func TestGroupMembersResponse_HasMore(t *testing.T) {
	mk := func(n int) []GroupMember { return make([]GroupMember, n) }
	assert.True(t, GroupMembersResponse{Members: mk(10), Count: 12}.HasMore(&GroupFilter{Limit: 10, Offset: 0}))
	assert.False(t, GroupMembersResponse{Members: mk(2), Count: 12}.HasMore(&GroupFilter{Limit: 10, Offset: 10}))
}

func TestListGroupMembersRequest_PathAndPagination(t *testing.T) {
	c := newLocalGroupClient("localhost")

	_, err := c.ListGroupMembersRequest("", nil)
	assert.Error(t, err)

	req, err := c.ListGroupMembersRequest("data/my-group", &GroupFilter{Limit: 5})
	assert.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "localhost/groups/data/my-group/members", req.URL.Path)
	assert.Equal(t, "limit=5", req.URL.RawQuery)
	assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
}

// TestRemoveGroupMemberURL_Escaping guards the member-id escaping fix: slashes
// in the id are preserved (they map to the route's *id glob) while other
// URL-significant characters are percent-escaped so the request URL is valid.
func TestRemoveGroupMemberURL_Escaping(t *testing.T) {
	c := newLocalGroupClient("https://host")

	testCases := []struct {
		id   string
		want string
	}{
		{id: "data/test/bob", want: "https://host/groups/myTestAccount/data/g/members/host/data/test/bob"},
		{id: "my host", want: "https://host/groups/myTestAccount/data/g/members/host/my%20host"},
		{id: "a@b.com", want: "https://host/groups/myTestAccount/data/g/members/host/a@b.com"},
		{id: "data/a b/c", want: "https://host/groups/myTestAccount/data/g/members/host/data/a%20b/c"},
	}

	// Force non-SaaS so the account segment is present and stable for assertion.
	c.config.Environment = EnvironmentSH
	for _, tc := range testCases {
		got, err := c.removeGroupMembershipURL("data/g", GroupMember{ID: tc.id, Kind: "host"})
		assert.NoErrorf(t, err, "member id %q", tc.id)
		assert.Equalf(t, tc.want, got, "member id %q", tc.id)
	}

	// A member id with a space must produce a request URL http.NewRequest accepts.
	req, err := c.RemoveGroupMemberRequest("data/g", GroupMember{ID: "my host", Kind: "host"})
	assert.NoError(t, err)
	assert.NotNil(t, req)
}

// TestGroupIdentifier_RejectsTraversal guards the path-traversal fix: a "." or
// ".." segment in a group or member identifier must be rejected, not escaped,
// since makeRouterURL's path.Join would otherwise resolve it and address a
// different resource.
func TestGroupIdentifier_RejectsTraversal(t *testing.T) {
	c := newLocalGroupClient("https://host")

	for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
		_, err := c.ReadGroupRequest(bad)
		assert.Errorf(t, err, "ReadGroupRequest(%q) must reject traversal", bad)

		_, err = c.RemoveGroupMemberRequest("data/g", GroupMember{ID: bad, Kind: "host"})
		assert.Errorf(t, err, "member id %q must be rejected", bad)

		_, err = c.RemoveGroupMemberRequest(bad, GroupMember{ID: "data/bob", Kind: "host"})
		assert.Errorf(t, err, "group id %q must be rejected", bad)
	}
}

// TestUpdateGroupRequest_AnnotationsPayload documents the update body shape.
// The service MERGES annotations (verified live), so there is no whole-map
// replacement via this route: a populated map is sent as-is; a nil map omits
// the field entirely (rather than serialising as `"annotations":null`).
// Removing an annotation is done through DeleteAnnotation, not an empty map.
func TestUpdateGroupRequest_AnnotationsPayload(t *testing.T) {
	c := newLocalGroupClient("https://host")

	req, err := c.UpdateGroupRequest("data/my-group", map[string]string{"team": "qa"})
	assert.NoError(t, err)
	body, _ := io.ReadAll(req.Body)
	assert.JSONEq(t, `{"annotations":{"team":"qa"}}`, string(body))

	// A nil map must not serialise as `"annotations":null` (omitempty drops it).
	req, err = c.UpdateGroupRequest("data/my-group", nil)
	assert.NoError(t, err)
	body, _ = io.ReadAll(req.Body)
	assert.JSONEq(t, `{}`, string(body))
}

func TestGroupExecutors_TypedResponses(t *testing.T) {
	ts, c := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/groups":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"name":"my-group","branch":"data","annotations":{"team":"witchers"},"created_at":"2026-01-02T03:04:05Z"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/groups":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"groups":[{"name":"g1","branch":"data"},{"name":"g2","branch":"data"}],"count":5}`))
		case r.Method == http.MethodGet && r.URL.Path == "/groups/data/my-group/members":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"members":[{"kind":"workload","id":"data/bob"}],"count":3}`))
		case r.Method == http.MethodGet && r.URL.Path == "/groups/data/my-group":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"name":"my-group","branch":"data","created_at":"2026-01-02T03:04:05Z"}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/groups/data/my-group":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"name":"my-group","branch":"data","annotations":{"team":"wolves"},"created_at":"2026-01-02T03:04:05Z"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/groups/data/my-group":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("unexpected " + r.Method + " " + r.URL.Path))
		}
	})
	defer ts.Close()

	created, err := c.V2().CreateGroup(Group{Name: "my-group", Branch: "data", Annotations: map[string]string{"team": "witchers"}})
	assert.NoError(t, err)
	assert.Equal(t, "my-group", created.Name)
	assert.Equal(t, "2026-01-02T03:04:05Z", created.CreatedAt)

	got, err := c.V2().ReadGroup("data/my-group")
	assert.NoError(t, err)
	assert.Equal(t, "my-group", got.Name)

	// UpdateGroup must PATCH the full Branch/Name identifier (/groups/data/my-group),
	// not just Name (/groups/my-group) — the server route above only matches the
	// former, so a regression to Name-only would 500 here.
	updated, err := c.V2().UpdateGroup(Group{Name: "my-group", Branch: "data", Annotations: map[string]string{"team": "wolves"}})
	assert.NoError(t, err)
	assert.Equal(t, "wolves", updated.Annotations["team"])

	list, err := c.V2().ReadGroups(&GroupFilter{Limit: 2, Offset: 0})
	assert.NoError(t, err)
	assert.Equal(t, 5, list.Count)
	assert.Len(t, list.Groups, 2)
	assert.True(t, list.HasMore(&GroupFilter{Limit: 2, Offset: 0}))

	members, err := c.V2().ListGroupMembers("data/my-group", nil)
	assert.NoError(t, err)
	assert.Equal(t, 3, members.Count)
	assert.Len(t, members.Members, 1)
	assert.Equal(t, "data/bob", members.Members[0].ID)

	assert.NoError(t, c.V2().DeleteGroup("data/my-group"))
}

func TestGroup_SelfHostedVersionGate(t *testing.T) {
	// Old Self-Hosted server -> permissive gate rejects with a version error.
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"1.0.0","services":{"possum":{"version":"1.0.0"}}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, err := NewClientFromJwt(Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSH,
	})
	assert.NoError(t, err)

	_, err = client.V2().CreateGroup(Group{Name: "g", Branch: "data"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), MinVersion)
}

// TestGroupURL_EscapesIdentifier guards the identifier-escaping fix: a group id
// with a space produces a valid (percent-escaped) URL while slashes (the route's
// *identifier glob) are preserved.
func TestGroupURL_EscapesIdentifier(t *testing.T) {
	c := newLocalGroupClient("localhost")
	c.config.Environment = EnvironmentSaaS // SaaS: no account segment

	req, err := c.ReadGroupRequest("data/my group")
	assert.NoError(t, err)
	assert.Equal(t, "localhost/groups/data/my%20group", req.URL.EscapedPath())

	req, err = c.ListGroupMembersRequest("data/my group", nil)
	assert.NoError(t, err)
	assert.Equal(t, "localhost/groups/data/my%20group/members", req.URL.EscapedPath())
}
