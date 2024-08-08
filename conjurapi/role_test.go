package conjurapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var roleTestPolicy = `
- !host bob
- !host jimmy
- !layer test-layer

- !variable secret

- !permit
  role: !host bob
  privilege: [ execute ]
  resource: !variable secret

- !grant
  role: !layer test-layer
  members: 
  - !host jimmy
  - !host bob
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

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()

	t.Run("Role exists returns true", roleExistent(conjur, "conjur:host:data/test/bob"))
	t.Run("Role exists returns false", roleNonexistent(conjur, "conjur:user:data/test/nonexistent"))
	t.Run("Role exists returns error", roleInvalid(conjur, ""))
}

func TestClient_Role(t *testing.T) {
	showRole := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := conjur.Role(id)
			assert.NoError(t, err)
		}
	}

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(roleTestPolicy)
	assert.NoError(t, err)

	conjur := utils.Client()

	t.Run("Shows a role", showRole(conjur, "conjur:host:data/test/bob"))
}

func TestClient_RoleMembers(t *testing.T) {
	listMembers := func(conjur *Client, id string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			members, err := conjur.RoleMembers(id)
			assert.NoError(t, err)
			assert.Len(t, members, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	conjur := utils.Client()
	_, err = utils.Setup(roleTestPolicy)
	assert.NoError(t, err)

	t.Run("List admin role members return 1 member", listMembers(conjur, fmt.Sprintf("conjur:user:%s", utils.AdminUser()), 1))
	t.Run("List role members return members", listMembers(conjur, "conjur:layer:data/test/test-layer", 3))
}

func TestClient_RoleMemberships(t *testing.T) {
	listMemberships := func(conjur *Client, id string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			memberships, err := conjur.RoleMemberships(id)
			assert.NoError(t, err)
			assert.Len(t, memberships, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(roleTestPolicy)
	assert.NoError(t, err)

	conjur := utils.Client()

	t.Run("List role memberships return memberships", listMemberships(conjur, "conjur:host:data/test/bob", 1))
	t.Run("List role memberships return no memberships", listMemberships(conjur, "conjur:layer:data/test/test-layer", 0))
}
