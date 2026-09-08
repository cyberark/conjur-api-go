package conjurapi

import (
	"net/http"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var emptyGroupPolicy = `
- !host bob
- !group test-users
`

var hostInGroupPolicy = `
- !host bob
- !group test-users

- !grant
  role: !group test-users
  members:
    - !host bob
`

func TestClientV2_AddGroupMember(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(emptyGroupPolicy)
	require.NoError(t, err)
	conjur := utils.Client().V2()

	testCases := []struct {
		name        string
		groupID     string
		member      GroupMember
		expectError string
	}{
		{
			name:    "Add valid host member",
			groupID: "data/test/test-users",
			member:  GroupMember{ID: "data/test/bob", Kind: "host"},
		},
		{
			name:        "Missing group ID",
			groupID:     "",
			member:      GroupMember{ID: "workload@example.com", Kind: "host"},
			expectError: "Must specify a Group ID",
		},
		{
			name:        "Missing member ID",
			groupID:     "data/test/test-users",
			member:      GroupMember{ID: "", Kind: "host"},
			expectError: "Must specify a Member",
		},
		{
			name:        "Invalid member kind",
			groupID:     "data/test/test-users",
			member:      GroupMember{ID: "workload@example.com", Kind: "invalid"},
			expectError: "Invalid member kind: invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			member, err := conjur.AddGroupMember(tc.groupID, tc.member)
			if tc.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, member)
			assert.Equal(t, tc.member.ID, member.ID)
			expectedPublic := toPublicKind(tc.member.Kind)
			assert.True(t,
				member.Kind == expectedPublic || member.Kind == tc.member.Kind,
				"Unexpected member kind: %s", member.Kind,
			)
		})
	}
}

// TestClientV2_AddGroupMemberServerError asserts that adding a member to a
// nonexistent group fails with a DISTINGUISHABLE not-found error — a
// *response.ConjurError carrying HTTP 404 — and returns a nil member rather than
// a pointer to a zero-value GroupMember. Every error case in
// TestClientV2_AddGroupMember fails client-side in Validate() before a request
// is sent, so this is the only case that exercises the response path.
func TestClientV2_AddGroupMemberServerError(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(emptyGroupPolicy)
	require.NoError(t, err)
	conjur := utils.Client().V2()

	// emptyGroupPolicy creates 'test-users', so this group does not exist.
	member, err := conjur.AddGroupMember("data/test/no-such-group", GroupMember{ID: "data/test/bob", Kind: "host"})

	require.Error(t, err, "adding a member to a nonexistent group should fail")
	assert.Nil(t, member, "member must be nil when the request fails, not a pointer to a zero-value struct")

	// The error must be classifiable as a 404 (the AC's "distinguishable
	// not-found"), not just any error.
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr, "error must be a *response.ConjurError")
	assert.Equal(t, http.StatusNotFound, conjurErr.Code, "nonexistent group must surface HTTP 404")
}

func TestClientV2_RemoveGroupMember(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(hostInGroupPolicy)
	require.NoError(t, err)
	conjur := utils.Client().V2()

	testCases := []struct {
		name        string
		groupID     string
		member      GroupMember
		expectError string
	}{
		{
			name:    "Remove valid host member",
			groupID: "data/test/test-users",
			member:  GroupMember{ID: "data/test/bob", Kind: "host"},
		},
		{
			name:        "Missing group ID",
			groupID:     "",
			member:      GroupMember{ID: "workload@example.com", Kind: "host"},
			expectError: "Must specify a Group ID",
		},
		{
			name:        "Missing member ID",
			groupID:     "data/test/test-users",
			member:      GroupMember{ID: "", Kind: "host"},
			expectError: "Must specify a Member",
		},
		{
			name:        "Invalid member kind",
			groupID:     "data/test/test-users",
			member:      GroupMember{ID: "workload@example.com", Kind: "invalid"},
			expectError: "Invalid member kind: invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conjur.RemoveGroupMember(tc.groupID, tc.member)
			if tc.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func toPublicKind(kind string) string {
	if kind == "host" {
		return "workload"
	}
	return kind
}
