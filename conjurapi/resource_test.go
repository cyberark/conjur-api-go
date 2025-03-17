package conjurapi

import (
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()

	t.Run(
		"Check an allowed permission for default role",
		checkAndAssert(conjur, assertSuccess, "conjur:variable:data/test/db-password"),
	)
	t.Run(
		"Check a permission on a non-existent resource",
		checkAndAssert(conjur, assertFailure, "conjur:variable:data/test/foobar"),
	)
	t.Run(
		"Check a permission on account-less resource",
		checkAndAssert(conjur, assertSuccess, "variable:data/test/db-password"),
	)
	t.Run(
		"Malformed resource id",
		checkAndAssert(conjur, assertError, "malformed_id"),
	)
}

func TestClient_CheckPermissionForRole(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()

	t.Run(
		"Check an allowed permission for a role",
		checkAndAssert(conjur, assertSuccess, "conjur:variable:data/test/db-password", "conjur:host:data/test/bob"),
	)
	t.Run(
		"Check a permission on a non-existent resource",
		checkAndAssert(conjur, assertFailure, "conjur:variable:data/test/foobar", "conjur:host:data/test/bob"),
	)
	t.Run(
		"Check no permission for a role",
		checkAndAssert(conjur, assertFailure, "conjur:variable:data/test/db-password", "conjur:host:data/test/jimmy"),
	)
	t.Run(
		"Check a permission with empty role",
		checkAndAssert(conjur, assertError, "conjur:variable:data/test/db-password", ""),
	)
	t.Run(
		"Check a permission for account-less role",
		checkAndAssert(conjur, assertSuccess, "variable:data/test/db-password", "host:data/test/bob"),
	)
	t.Run(
		"Malformed resource id",
		checkAndAssert(conjur, assertError, "malformed_id", "conjur:host:data/test/bob"),
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

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()

	t.Run("Resource exists returns true", resourceExistent(conjur, "conjur:variable:data/test/db-password"))
	t.Run("Resource exists returns false", resourceNonexistent(conjur, "conjur:variable:data/test/nonexistent"))
}

var resourceTestPolicy = `
- !host 
  id: kate
  annotations:
    authn/api-key: true

- !policy
  id: database-policy
  owner: !host kate
  body:
    - !host dev/db-host
    - !host prod/db-host
    - &variables
      - !variable secret1
      - !variable secret2
      - !variable secret3
      - !variable secret4
      - !variable secret5
      - !variable secret6
      - !variable prod/db-login
      - !variable prod/db-password

- !permit
  role: !host database-policy/prod/db-host
  privilege: [ read ]
  resource: !variable database-policy/prod/db-login

- !permit
  role: !host database-policy/prod/db-host
  privilege: [ read ]
  resource: !variable database-policy/prod/db-password
`

func TestClient_Resources(t *testing.T) {
	listResources := func(conjur *Client, filter *ResourceFilter, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			resources, err := conjur.Resources(filter)
			require.NoError(t, err)
			assert.Len(t, resources, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)

	keys, err := utils.Setup(resourceTestPolicy)
	require.NoError(t, err)

	config := Config{}
	config.mergeEnv()

	// file deepcode ignore NoHardcodedCredentials/test: This is a test file
	conjur, err := NewClientFromKey(config, authn.LoginPair{Login: "host/data/test/kate", APIKey: keys["kate"]})
	require.NoError(t, err)

	t.Run("Lists all resources", listResources(conjur, nil, 11))
	t.Run("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}, 8))
	t.Run("Lists resources that start with db", listResources(conjur, &ResourceFilter{Search: "db"}, 4))
	t.Run("Lists variables that start with prod/database", listResources(conjur, &ResourceFilter{Search: "prod/db", Kind: "variable"}, 2))
	t.Run("Lists resources and limit result to 1", listResources(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Lists resources after the first", listResources(conjur, &ResourceFilter{Offset: 1, Limit: 50}, 10))
	t.Run("Lists resources that prod/db-host can see", listResources(conjur, &ResourceFilter{Role: "conjur:host:data/test/database-policy/prod/db-host"}, 2))
}

func TestClient_ResourcesCount(t *testing.T) {
	listResourcesCount := func(conjur *Client, filter *ResourceFilter, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			resourcesCount, err := conjur.ResourcesCount(filter)
			require.NoError(t, err)
			assert.Equal(t, resourcesCount.Count, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)

	keys, err := utils.Setup(resourceTestPolicy)
	require.NoError(t, err)

	config := Config{}
	config.mergeEnv()

	// file deepcode ignore NoHardcodedCredentials/test: This is a test file
	conjur, err := NewClientFromKey(config, authn.LoginPair{Login: "host/data/test/kate", APIKey: keys["kate"]})
	require.NoError(t, err)

	t.Run("Counts all resources", listResourcesCount(conjur, nil, 11))
	t.Run("Counts resources filtered by kind", listResourcesCount(conjur, &ResourceFilter{Kind: "variable"}, 8))
	t.Run("Counts resources that start with db", listResourcesCount(conjur, &ResourceFilter{Search: "db"}, 4))
	t.Run("Counts variables that start with prod/database", listResourcesCount(conjur, &ResourceFilter{Search: "prod/db", Kind: "variable"}, 2))
	t.Run("Counts resources and limit result to 1", listResourcesCount(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Counts resources when offset is used", listResourcesCount(conjur, &ResourceFilter{Offset: 1, Limit: 50}, 10))
	t.Run("Counts resources for role with limited access to resources", listResourcesCount(conjur, &ResourceFilter{Role: "conjur:host:data/test/database-policy/prod/db-host"}, 2))
}

func TestClient_Resource(t *testing.T) {
	showResource := func(conjur *Client, id string) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := conjur.Resource(id)
			assert.NoError(t, err)
		}
	}

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()
	t.Run("Shows a resource", showResource(conjur, "conjur:variable:data/test/db-password"))
}

func TestClient_ResourceIDs(t *testing.T) {
	listResourceIDs := func(conjur *Client, filter *ResourceFilter, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			resources, err := conjur.ResourceIDs(filter)
			assert.NoError(t, err)
			assert.Len(t, resources, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)

	keys, err := utils.Setup(resourceTestPolicy)
	require.NoError(t, err)

	config := Config{}
	config.mergeEnv()

	conjur, err := NewClientFromKey(config, authn.LoginPair{Login: "host/data/test/kate", APIKey: keys["kate"]})
	require.NoError(t, err)

	t.Run("Lists all resources", listResourceIDs(conjur, nil, 11))
	t.Run("Lists resources by kind", listResourceIDs(conjur, &ResourceFilter{Kind: "variable"}, 8))
	t.Run("Lists resources that start with db", listResourceIDs(conjur, &ResourceFilter{Search: "db"}, 4))
	t.Run("Lists variables that start with prod/database", listResourceIDs(conjur, &ResourceFilter{Search: "prod/db", Kind: "variable"}, 2))
	t.Run("Lists resources and limit result to 1", listResourceIDs(conjur, &ResourceFilter{Limit: 1}, 1))
	t.Run("Lists resources after the first", listResourceIDs(conjur, &ResourceFilter{Offset: 1, Limit: 50}, 10))
	t.Run("Lists resources that prod/db-host can see", listResourceIDs(conjur, &ResourceFilter{Role: "conjur:host:data/test/database-policy/prod/db-host"}, 2))
}

func TestClient_PermittedRoles(t *testing.T) {
	listPermittedRoles := func(conjur *Client, resourceID string, expected int) func(t *testing.T) {
		return func(t *testing.T) {
			roles, err := conjur.PermittedRoles(resourceID, "execute")
			assert.NoError(t, err)
			assert.Len(t, roles, expected)
		}
	}

	utils, err := NewTestUtils(&Config{})
	assert.NoError(t, err)

	_, err = utils.Setup(utils.DefaultTestPolicy())
	assert.NoError(t, err)
	conjur := utils.Client()
	assert.NoError(t, err)

	t.Run("Lists permitted roles on a variable", listPermittedRoles(conjur, "conjur:variable:data/test/db-password", 4))
}
