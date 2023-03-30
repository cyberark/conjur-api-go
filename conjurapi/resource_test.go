package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type checkAssertion func(t *testing.T, result bool, err error)

func assertSuccess(t *testing.T, result bool, err error) {
	assert.True(t, result)
	assert.NoError(t, err)
}

func assertFailure(t *testing.T, result bool, err error) {
	assert.False(t, result)
	assert.NoError(t, err)
}

func assertError(t *testing.T, result bool, err error) {
	assert.False(t, result)
	assert.Error(t, err)
}

func checkAndAssert(
	conjur *Client,
	assertion checkAssertion,
	args ...string,
) func(t *testing.T) {
	return func(t *testing.T) {
		var result bool
		var err error

		if len(args) == 1 {
			result, err = conjur.CheckPermission(args[0], "execute")
		} else if len(args) == 2 {
			result, err = conjur.CheckPermissionForRole(args[0], args[1], "execute")
		}

		assertion(t, result, err)
	}
}

func TestClient_CheckPermission(t *testing.T) {
	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run(
		"Check an allowed permission for default role",
		checkAndAssert(conjur, assertSuccess, "cucumber:variable:db-password"),
	)
	t.Run(
		"Check a permission on a non-existent resource",
		checkAndAssert(conjur, assertFailure, "cucumber:variable:foobar"),
	)
	t.Run(
		"Check a permission on account-less resource",
		checkAndAssert(conjur, assertSuccess, "variable:db-password"),
	)
}

func TestClient_CheckPermissionForRole(t *testing.T) {
	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run(
		"Check an allowed permission for a role",
		checkAndAssert(conjur, assertSuccess, "cucumber:variable:db-password", "cucumber:user:alice"),
	)
	t.Run(
		"Check a permission on a non-existent resource",
		checkAndAssert(conjur, assertFailure, "cucumber:variable:foobar", "cucumber:user:alice"),
	)
	t.Run(
		"Check no permission for a role",
		checkAndAssert(conjur, assertFailure, "cucumber:variable:db-password", "cucumber:host:bob"),
	)
	t.Run(
		"Check a permission with empty role",
		checkAndAssert(conjur, assertError, "cucumber:variable:db-password", ""),
	)
	t.Run(
		"Check a permission for account-less role",
		checkAndAssert(conjur, assertSuccess, "variable:db-password", "user:alice"),
	)
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

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
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

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run("Lists all resources", listResources(conjur, nil, 13))
	t.Run("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}, 7))
	t.Run("Lists resources that start with db", listResources(conjur, &ResourceFilter{Search: "db"}, 2))
	t.Run("Lists variables that start with prod/database", listResources(conjur, &ResourceFilter{Search: "prod/database", Kind: "variable"}, 2))
	t.Run("Lists variables that start with prod", listResources(conjur, &ResourceFilter{Search: "prod", Kind: "variable"}, 4))
	t.Run("Lists resources and limit result to 1", listResources(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Lists resources after the first", listResources(conjur, &ResourceFilter{Offset: 1}, 10))
	t.Run("Lists resources that alice can see", listResources(conjur, &ResourceFilter{Role: "cucumber:user:alice"}, 1))
}

func TestClient_Resource(t *testing.T) {
	showResource := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := conjur.Resource(id)
			assert.NoError(t, err)
		}
	}

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
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

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run("Lists all resources", listResourceIDs(conjur, nil, 13))
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

	conjur, err := conjurSetup(&Config{}, defaultTestPolicy)
	assert.NoError(t, err)

	t.Run("Lists permitted roles on a variable", listPermittedRoles(conjur, "cucumber:variable:db-password", 2))
}
