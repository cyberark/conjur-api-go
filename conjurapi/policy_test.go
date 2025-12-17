package conjurapi

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testCases = []struct {
		name       string
		policyMode PolicyMode
		expectErr  string
	}{
		{
			name:       "PolicyModePut",
			policyMode: PolicyModePut,
		},
		{
			name:       "PolicyModePost",
			policyMode: PolicyModePost,
		},
		{
			name:       "PolicyModePatch",
			policyMode: PolicyModePatch,
		},
		{
			name:       "Invalid PolicyMode",
			policyMode: 99,
			expectErr:  "Invalid PolicyMode: 99",
		},
	}
)

func TestPolicy_LoadPolicyModes(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hostname := randomName(12)
			policy := fmt.Sprintf(
				`- !host %s`,
				hostname,
			)

			resp, err := conjur.LoadPolicy(
				tc.policyMode,
				utils.PolicyBranch(),
				strings.NewReader(policy),
			)

			if tc.expectErr == "" {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, resp.Version, uint32(1))
			} else {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expectErr)
				assert.Nil(t, resp)
			}
		})
	}
}

func TestPolicy_LoadPolicy(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	t.Run("A new role is reported in the policy load response", func(t *testing.T) {
		hostname := randomName(12)
		policy := fmt.Sprintf(`
- !host
  id: %s
  annotations:
    authn/api-key: true`, hostname)

		resp, err := conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		assert.NoError(t, err)
		createdRole, ok := resp.CreatedRoles["conjur:host:"+utils.IDWithPath(hostname)]
		assert.NotEmpty(t, createdRole.ID)
		assert.NotEmpty(t, createdRole.APIKey)
		assert.True(t, ok)
	})

	t.Run("Given invalid login credentials", func(t *testing.T) {
		t.Run("Returns 401", func(t *testing.T) {
			// deepcode ignore NoHardcodedCredentials/test: This is a test file
			conjurClient, err := NewClientFromKey(*config, authn.LoginPair{Login: "invalid-login", APIKey: "invalid-key"})
			assert.NoError(t, err)

			resp, err := conjurClient.LoadPolicy(PolicyModePut, utils.PolicyBranch(), strings.NewReader(""))

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.IsType(t, &response.ConjurError{}, err)
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 401, conjurError.Code)
		})
	})
}

func TestPolicy_DryRunPolicy(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Dry run not supported on Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)
			conjur := utils.Client()

			resp, err := conjur.DryRunPolicy(
				PolicyModePut,
				utils.PolicyBranch(),
				strings.NewReader(""),
			)

			require.Error(t, err)
			assert.EqualError(t, err, "Policy Dry Run is not supported in Secrets Manager SaaS")
			assert.Nil(t, resp)
		})
		// Skip the rest of the tests when running against Secrets Manager SaaS
		return
	}

	t.Run("A policy is successfully validated", func(t *testing.T) {
		hostname := randomName(12)
		policy := fmt.Sprintf(
			`- !host %s`,
			hostname,
		)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		assert.NoError(t, err)
		assert.Equal(t, "Valid YAML", resp.Status)
		assert.Empty(t, resp.Errors)
	})

	t.Run("A policy dryrun returns the created resources", func(t *testing.T) {
		// difference from this
		originalPolicy := fmt.Sprintf(
			`# `,
		)
		// from Policy Dry Run SD, "Simple Examples: Raw Diff, Mapper, DTOs":
		policy := fmt.Sprintf(`
      - !policy
        id: example
        body:
          - !user
            id: barrett
            restricted_to: [ "127.0.0.1" ]
            annotations:
              key: value
          - !variable
            id: secret01
            annotations:
              key: value
          - !permit
            role: !user barrett
            privileges: [ read, execute ]
            resources:
              - !variable secret01
        `)

		_, err := conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(originalPolicy),
		)
		require.NoError(t, err)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		// General assertions that the request was successful
		assert.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.Equal(t, "Valid YAML", resp.Status)

		// Verify the shape and spot check the content
		require.NotNil(t, resp.Created)
		assert.Len(t, resp.Created.Items, 3)
		iUser := 0
		iPol := 1
		iVar := 2
		resourceUser := resp.Created.Items[iUser]
		assert.Equal(t, "conjur:policy:data/test", resourceUser.Owner)
		resourcePolicy := resp.Created.Items[iPol]
		assert.NotNil(t, resourcePolicy.Members)
		resourceVariable := resp.Created.Items[iVar]
		assert.Equal(t, "data/test/example/secret01", resourceVariable.Id)
	})

	t.Run("A policy dry run returns the updated resources", func(t *testing.T) {
		hostname := randomName(12)
		originalPolicy := fmt.Sprintf(
			`- !host %s`,
			hostname,
		)

		conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(originalPolicy),
		)

		// Update the host to add an annotation
		updatedPolicy := fmt.Sprintf(
			`
- !host
  id: %s
  annotations:
    name: "test name"
`,
			hostname,
		)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(updatedPolicy),
		)

		// General assertions that the request was successful
		assert.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.Equal(t, "Valid YAML", resp.Status)

		expectedHostID := fmt.Sprintf("data/test/%s", hostname)

		// Verify the specific content of the updated policy resources
		assert.Len(t, resp.Updated.Before.Items, 1)
		before := resp.Updated.Before.Items[0]
		assert.Equal(t, before.Id, expectedHostID)
		assert.Empty(t, before.Annotations)

		assert.Len(t, resp.Updated.After.Items, 1)
		after := resp.Updated.After.Items[0]
		assert.Equal(t, after.Id, expectedHostID)
		assert.Equal(t, after.Annotations["name"], "test name")
	})

	t.Run("A policy dry run PATCH returns the deleted resources", func(t *testing.T) {
		originalPolicy := `
- !user alice
- !user bob
- !user carol
- !user dan
- !user eve
`
		deletingPolicy := `
- !delete
  record: !user bob
- !delete
  record: !user carol
`
		beforeUpdate := `
[{
	"identifier":"conjur:policy:data/test",
	"id":"data/test",
	"type":"policy",
	"owner":"conjur:policy:data",
	"policy":"conjur:policy:root",
	"annotations":{},"permissions":{},
	"members":["conjur:policy:data"],
	"memberships":[
		"conjur:user:alice@data-test",
		"conjur:user:bob@data-test",
		"conjur:user:carol@data-test",
		"conjur:user:dan@data-test",
		"conjur:user:eve@data-test"
	],
	"restricted_to":[]
}]
`
		afterUpdate := `
[{
	"identifier":"conjur:policy:data/test",
	"id":"data/test",
	"type":"policy",
	"owner":"conjur:policy:data",
	"policy":"conjur:policy:root",
	"annotations":{},"permissions":{},
	"members":["conjur:policy:data"],
	"memberships":[
		"conjur:user:alice@data-test",
		"conjur:user:dan@data-test",
		"conjur:user:eve@data-test"
	],
	"restricted_to":[]
}]
`
		// Load the originalPolicy
		origResp, origErr := conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(originalPolicy),
		)

		// Then load the deletingPolicy
		dryRunResp, dryRunErr := conjur.DryRunPolicy(
			PolicyModePatch,
			utils.PolicyBranch(),
			strings.NewReader(deletingPolicy),
		)

		// General assertions that the requests were successful
		assert.NoError(t, origErr)
		assert.NoError(t, dryRunErr)
		assert.Len(t, origResp.CreatedRoles, 5)
		assert.Equal(t, dryRunResp.Status, "Valid YAML")
		assert.Len(t, dryRunResp.Created.Items, 0)

		// Verify the specific content of the deleted policy resources
		assert.Len(t, dryRunResp.Deleted.Items, 2)
		deletedItem1 := dryRunResp.Deleted.Items[0]
		deletedItem2 := dryRunResp.Deleted.Items[1]
		assert.Equal(t, deletedItem1.Id, "bob@data-test")
		assert.Equal(t, deletedItem2.Id, "carol@data-test")

		// Check that memberships have been updated appropriately
		before, bErr := json.Marshal(dryRunResp.Updated.Before.Items)
		assert.JSONEq(t, beforeUpdate, string(before))
		assert.NoError(t, bErr)
		after, aErr := json.Marshal(dryRunResp.Updated.After.Items)
		assert.JSONEq(t, afterUpdate, string(after))
		assert.NoError(t, aErr)
	})

	t.Run("A policy dry run PUT returns the deleted resources", func(t *testing.T) {
		originalPolicy := `
- !user fran
- !user gary
- !user hans
- !user ian
- !user jill
`
		newPolicy := `
- !user gary
- !user hans
- !user kay
`
		beforeUpdate := `
[{
	"identifier":"conjur:policy:data/test",
	"id":"data/test",
	"type":"policy",
	"owner":"conjur:policy:data",
	"policy":"conjur:policy:root",
	"annotations":{},"permissions":{},
	"members":["conjur:policy:data"],
	"memberships":[
		"conjur:user:fran@data-test",
		"conjur:user:gary@data-test",
		"conjur:user:hans@data-test",
		"conjur:user:ian@data-test",
		"conjur:user:jill@data-test"
	],
	"restricted_to":[]
}]
`
		afterUpdate := `
[{
	"identifier":"conjur:policy:data/test",
	"id":"data/test",
	"type":"policy",
	"owner":"conjur:policy:data",
	"policy":"conjur:policy:root",
	"annotations":{},"permissions":{},
	"members":["conjur:policy:data"],
	"memberships":[
		"conjur:user:gary@data-test",
		"conjur:user:hans@data-test",
		"conjur:user:kay@data-test"
	],
	"restricted_to":[]
}]
`
		conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(``),
		)

		// Load the originalPolicy
		origResp, origErr := conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(originalPolicy),
		)

		// Then load the deletingPolicy
		dryRunResp, dryRunErr := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(newPolicy),
		)

		// General assertions that the requests were successful
		assert.NoError(t, origErr)
		assert.NoError(t, dryRunErr)
		assert.Len(t, origResp.CreatedRoles, 5)
		assert.Equal(t, dryRunResp.Status, "Valid YAML")

		// Verify the specific content of the deleted policy resources
		assert.Len(t, dryRunResp.Deleted.Items, 3)
		deletedItem1 := dryRunResp.Deleted.Items[0]
		deletedItem2 := dryRunResp.Deleted.Items[1]
		deletedItem3 := dryRunResp.Deleted.Items[2]
		assert.Equal(t, deletedItem1.Id, "fran@data-test")
		assert.Equal(t, deletedItem2.Id, "ian@data-test")
		assert.Equal(t, deletedItem3.Id, "jill@data-test")

		// Check that memberships have been updated appropriately
		before, bErr := json.Marshal(dryRunResp.Updated.Before.Items)
		assert.JSONEq(t, beforeUpdate, string(before))
		assert.NoError(t, bErr)
		after, aErr := json.Marshal(dryRunResp.Updated.After.Items)
		assert.JSONEq(t, afterUpdate, string(after))
		assert.NoError(t, aErr)

		// Check that new user was created successfully
		assert.Len(t, dryRunResp.Created.Items, 1)
		createdItem := dryRunResp.Created.Items[0]
		assert.Equal(t, createdItem.Id, "kay@data-test")
	})

	t.Run("A policy is not successfully validated", func(t *testing.T) {
		hostname := randomName(12)
		policy := fmt.Sprintf(
			`- host %s`,
			hostname,
		)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		assert.Nil(t, err)
		assert.Equal(t, "Invalid YAML", resp.Status)
		require.Equal(t, 1, len(resp.Errors))
		assert.Equal(t, 0, resp.Errors[0].Line)
		assert.Equal(t, 0, resp.Errors[0].Column)
		assert.Contains(t, resp.Errors[0].Message, "undefined method 'referenced_records' for")
	})

	t.Run("Returns error on older Conjur versions", func(t *testing.T) {
		// Mock the Conjur version to be older than the minimum required version

		// Store the original values
		originalMockEnterpriseInfo := mockEnterpriseInfo
		originalMockRootResponse := mockRootResponse
		originalMockRootResponseContentType := mockRootResponseContentType

		// Set the mock values
		mockEnterpriseInfo = ""
		mockRootResponse = `{"version": "1.21.0-11"}`
		mockRootResponseContentType = "application/json"

		// Restore the original values after the test
		defer func() {
			mockEnterpriseInfo = originalMockEnterpriseInfo
			mockRootResponse = originalMockRootResponse
			mockRootResponseContentType = originalMockRootResponseContentType
		}()

		mockServer, mockClient := createMockConjurClient(t)
		defer mockServer.Close()

		resp, err := mockClient.DryRunPolicy(PolicyModePut, "test", strings.NewReader(""))
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "Policy Dry Run is not supported in Secrets Manager versions older than 1.21.1")

		fetchResp, err := mockClient.FetchPolicy(utils.PolicyBranch(), false, 64, 100000)
		assert.Error(t, err)
		assert.Nil(t, fetchResp)
		assert.Contains(t, err.Error(), "Policy Fetch is not supported in Secrets Manager versions older than 1.21.1")
	})
}

func TestPolicy_FetchPolicy(t *testing.T) {
	// setup
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	require.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	hostname := "bob"
	policy := fmt.Sprintf(
		`- !host %s`,
		hostname,
	)

	_, err = conjur.LoadPolicy(
		PolicyModePut,
		utils.PolicyBranch(),
		strings.NewReader(policy),
	)
	assert.NoError(t, err)

	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Fetch policy not supported on Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)
			conjur := utils.Client()

			resp, err := conjur.FetchPolicy(utils.PolicyBranch(), false, 64, 100000)

			require.Error(t, err)
			assert.EqualError(t, err, "Policy Fetch is not supported in Secrets Manager SaaS")
			assert.Nil(t, resp)
		})
		// Skip the rest of the tests when running against Secrets Manager SaaS
		return
	}

	t.Run("Policy response is formatted as YAML", func(t *testing.T) {

		resp, err := conjur.FetchPolicy(utils.PolicyBranch(), false, 64, 100000)
		require.NoError(t, err)
		require.NotEmpty(t, resp)
		policyYAML := fmt.Sprintf(`---
- !policy
  id: test
  body:
  - !host %s
`, hostname)
		assert.Equal(t, policyYAML, string(resp))
	})

	t.Run("Policy response is formatted as JSON", func(t *testing.T) {

		resp, err := conjur.FetchPolicy(utils.PolicyBranch(), true, 64, 100000)
		require.NoError(t, err)
		require.NotEmpty(t, resp)
		policyJSON := fmt.Sprintf(`[{"policy":{"id":"test","body":[{"host":{"id":"%s"}}]}}]`, hostname)
		assert.Equal(t, policyJSON, string(resp))
	})

	t.Run("Given invalid policy id", func(t *testing.T) {
		t.Run("Returns 404", func(t *testing.T) {

			resp, err := conjur.FetchPolicy("non/existing/policy", false, 64, 100000)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.IsType(t, &response.ConjurError{}, err)
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 404, conjurError.Code)
		})
	})
}

func randomName(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	result := make([]byte, length)
	for i := range result {
		result[i] = chars[randomizer.Intn(len(chars))]
	}

	return string(result)
}
