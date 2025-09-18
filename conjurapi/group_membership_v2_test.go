package conjurapi

import (
	"os"
	"testing"

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
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.member.ID, member.ID)
					assert.Equal(t, toPublicKind(tc.member.Kind), member.Kind)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}
		})
	}
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
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}
		})
	}
}

func toPublicKind(kind string) string {
	if kind == "host" {
		return "workload"
	}
	return kind
}
