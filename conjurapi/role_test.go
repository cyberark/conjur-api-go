package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var roleTestPolicy = `
- !user alice
- !host jimmy
- !layer test-layer

- !variable secret

- !permit
  role: !user alice
  privilege: [ execute ]
  resource: !variable secret

- !grant
  role: !layer test-layer
  members: 
  - !host jimmy
  - !user alice
`

func TestClient_RoleExists(t *testing.T) {
	roleExistent := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			exists, err := conjur.RoleExists(id)
			assert.NoError(t, err)
			assert.True(t, exists)
		}
	}

	roleNonexistent := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			exists, err := conjur.RoleExists(id)
			assert.NoError(t, err)
			assert.False(t, exists)
		}
	}

	roleInvalid := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			exists, err := conjur.RoleExists(id)
			assert.Error(t, err)
			assert.False(t, exists)
		}
	}

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run("Role exists returns true", roleExistent(conjur, "cucumber:user:alice"))
	t.Run("Role exists returns false", roleNonexistent(conjur, "cucumber:user:nonexistent"))
	t.Run("Role exists returns error", roleInvalid(conjur, ""))
}

func TestClient_Role(t *testing.T) {
	showRole := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := conjur.Role(id)
			assert.NoError(t, err)
		}
	}

	conjur, err := conjurSetup(&Config{}, roleTestPolicy)
	assert.NoError(t, err)

	t.Run("Shows a role", showRole(conjur, "cucumber:user:alice"))
}

func TestClient_RoleMembers(t *testing.T) {
	listMembers := func(conjur *Client, id string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			members, err := conjur.RoleMembers(id)
			assert.NoError(t, err)
			assert.Len(t, members, expected)
		}
	}

	conjur, err := conjurSetup(&Config{}, roleTestPolicy)
	assert.NoError(t, err)

	t.Run("List role members return no members", listMembers(conjur, "cucumber:user:admin", 0))
	t.Run("List role members return members", listMembers(conjur, "cucumber:layer:test-layer", 3))
}

func TestClient_RoleMemberships(t *testing.T) {
	listMemberships := func(conjur *Client, id string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			memberships, err := conjur.RoleMemberships(id)
			assert.NoError(t, err)
			assert.Len(t, memberships, expected)
		}
	}

	conjur, err := conjurSetup(&Config{}, roleTestPolicy)
	assert.NoError(t, err)

	t.Run("List role memberships return memberships", listMemberships(conjur, "cucumber:user:admin", 4))
	t.Run("List role memberships return no memberships", listMemberships(conjur, "cucumber:layer:test-layer", 0))
}
