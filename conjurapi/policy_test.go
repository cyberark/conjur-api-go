package conjurapi

import (
	"fmt"
	"math/rand"
	"os"
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

	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	login := os.Getenv("CONJUR_AUTHN_LOGIN")

	conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
	assert.NoError(t, err)

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			username := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, username)

			resp, err := conjur.LoadPolicy(
				tc.policyMode,
				"root",
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

		username := string(result)
		policy := fmt.Sprintf(`
- !user %s
`, username)

		resp, err := conjur.LoadPolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)

		assert.NoError(t, err)
		createdRole, ok := resp.CreatedRoles["cucumber:user:"+username]
		assert.NotEmpty(t, createdRole.ID)
		assert.NotEmpty(t, createdRole.APIKey)
		assert.True(t, ok)
	})

	t.Run("Given invalid login credentials", func(t *testing.T) {
		login = "invalid-user"

		t.Run("Returns 401", func(t *testing.T) {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			resp, err := conjur.LoadPolicy(PolicyModePut, "root", strings.NewReader(""))

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

		username := string(result)
		policy := fmt.Sprintf(`
- !user %s
`, username)

		resp, err := conjur.ValidatePolicy(
			PolicyModePut,
			"root",
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

		username := string(result)
		policy := fmt.Sprintf(`
- user %s
`, username)

		resp, err := conjur.ValidatePolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)

		assert.Nil(t, err)
		assert.Equal(t, "Invalid YAML", resp.Status)
		assert.Equal(t, 1, len(resp.Errors))
		assert.Equal(t, 0, resp.Errors[0].Line)
		assert.Equal(t, 0, resp.Errors[0].Column)
		assert.Equal(t, fmt.Sprintf("undefined method `referenced_records' for \"user %s\":String\n", username), resp.Errors[0].Message)
	})
}
