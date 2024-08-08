package conjurapi

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
)

var testCases = []struct {
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

func TestClient_LoadPolicy(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	conjur := utils.Client()

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hostname := "bob"
			policy := fmt.Sprintf(`
- !host %s
`, hostname)

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

	t.Run("A new role is reported in the policy load response", func(t *testing.T) {
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
		result := make([]byte, 12)
		for i := range result {
			result[i] = chars[randomizer.Intn(len(chars))]
		}

		hostname := string(result)
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

	t.Run("A policy is successfully validated", func(t *testing.T) {
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
		result := make([]byte, 12)
		for i := range result {
			result[i] = chars[randomizer.Intn(len(chars))]
		}

		hostname := string(result)
		policy := fmt.Sprintf(`
- !host %s`, hostname)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		assert.NoError(t, err)
		assert.Equal(t, "Valid YAML", resp.Status)
		assert.Empty(t, resp.Errors)
	})
	t.Run("A policy is not successfully validated", func(t *testing.T) {
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
		result := make([]byte, 12)
		for i := range result {
			result[i] = chars[randomizer.Intn(len(chars))]
		}

		hostname := string(result)
		policy := fmt.Sprintf(`
- host %s
`, hostname)

		resp, err := conjur.DryRunPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		assert.Nil(t, err)
		assert.Equal(t, "Invalid YAML", resp.Status)
		assert.Equal(t, 1, len(resp.Errors))
		assert.Equal(t, 0, resp.Errors[0].Line)
		assert.Equal(t, 0, resp.Errors[0].Column)
		assert.Equal(t, fmt.Sprintf("undefined method `referenced_records' for \"host %s\":String\n", hostname), resp.Errors[0].Message)
	})
}

func TestClient_FetchPolicy(t *testing.T) {
	// setup
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	conjur := utils.Client()

	hostname := "bob"
	policy := fmt.Sprintf(`
- !host %s
`, hostname)

	_, err = conjur.LoadPolicy(
		PolicyModePut,
		utils.PolicyBranch(),
		strings.NewReader(policy),
	)
	assert.NoError(t, err)

	t.Run("Policy response is formatted as YAML", func(t *testing.T) {

		resp, err := conjur.FetchPolicy(utils.PolicyBranch(), false, 64, 100000)
		policyYAML := fmt.Sprintf(`---
- !policy
  id: test
  body:
  - !host %s
`, hostname)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp)
		assert.Equal(t, policyYAML, string(resp))
	})

	t.Run("Policy response is formatted as JSON", func(t *testing.T) {

		resp, err := conjur.FetchPolicy(utils.PolicyBranch(), true, 64, 100000)
		policyJSON := fmt.Sprintf(`[{"policy":{"id":"test","body":[{"host":{"id":"%s"}}]}}]`, hostname)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp)
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
