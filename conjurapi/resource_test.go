package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_CheckPermission(t *testing.T) {
	checkAllowed := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			allowed, err := conjur.CheckPermission(id, "execute")

			assert.NoError(t, err)
			assert.True(t, allowed)
		}
	}

	checkNonExisting := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			allowed, err := conjur.CheckPermission(id, "execute")

			assert.NoError(t, err)
			assert.False(t, allowed)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Check an allowed permission", checkAllowed(conjur, "cucumber:variable:db-password"))

	t.Run("Check a permission on a non-existent resource", checkNonExisting(conjur, "cucumber:variable:foobar"))
}

func TestClient_ResourceExists(t *testing.T) {
	resourceExistent := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			exists, err := conjur.ResourceExists(id)
			assert.NoError(t, err)
			assert.True(t, exists)
		}
	}

	resourceNonexistent := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			exists, err := conjur.ResourceExists(id)
			assert.NoError(t, err)
			assert.False(t, exists)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Resource exists returns true", resourceExistent(conjur, "cucumber:variable:db-password"))
	t.Run("Resource exists returns false", resourceNonexistent(conjur, "cucumber:variable:nonexistent"))
}

func TestClient_Resources(t *testing.T) {
	listResources := func(conjur *Client, filter *ResourceFilter, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			resources, err := conjur.Resources(filter)
			assert.NoError(t, err)
			assert.Len(t, resources, expected)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Lists all resources", listResources(conjur, nil, 12))
	t.Run("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}, 7))
	t.Run("Lists resources that start with db", listResources(conjur, &ResourceFilter{Search: "db"}, 2))
	t.Run("Lists variables that start with prod/database", listResources(conjur, &ResourceFilter{Search: "prod/database", Kind: "variable"}, 2))
	t.Run("Lists variables that start with prod", listResources(conjur, &ResourceFilter{Search: "prod", Kind: "variable"}, 4))
	t.Run("Lists resources and limit result to 1", listResources(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Lists resources after the first", listResources(conjur, &ResourceFilter{Offset: 1}, 10))
}

func TestClient_Resource(t *testing.T) {
	showResource := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := conjur.Resource(id)
			assert.NoError(t, err)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Shows a resource", showResource(conjur, "cucumber:variable:db-password"))
}

func TestClient_ResourceIDs(t *testing.T) {
	listResourceIDs := func(conjur *Client, filter *ResourceFilter, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			resources, err := conjur.ResourceIDs(filter)
			assert.NoError(t, err)
			assert.Len(t, resources, expected)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Lists all resources", listResourceIDs(conjur, nil, 12))
	t.Run("Lists resources by kind", listResourceIDs(conjur, &ResourceFilter{Kind: "variable"}, 7))
	t.Run("Lists resources that start with db", listResourceIDs(conjur, &ResourceFilter{Search: "db"}, 2))
	t.Run("Lists variables that start with prod/database", listResourceIDs(conjur, &ResourceFilter{Search: "prod/database", Kind: "variable"}, 2))
	t.Run("Lists variables that start with prod", listResourceIDs(conjur, &ResourceFilter{Search: "prod", Kind: "variable"}, 4))
	t.Run("Lists resources and limit result to 1", listResourceIDs(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Lists resources after the first", listResourceIDs(conjur, &ResourceFilter{Offset: 1}, 10))
}

func TestClient_PermittedRoles(t *testing.T) {
	listPermittedRoles := func(conjur *Client, resourceID string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			roles, err := conjur.PermittedRoles(resourceID, "execute")
			assert.NoError(t, err)
			assert.Len(t, roles, expected)
		}
	}

	conjur, err := conjurDefaultSetup()
	assert.NoError(t, err)

	t.Run("Lists permitted roles on a variable", listPermittedRoles(conjur, "cucumber:variable:db-password", 2))
}
