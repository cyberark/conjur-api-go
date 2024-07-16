package conjurapi

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
)

func TestClient_RetrieveSecret(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	conjur := utils.Client()

	t.Run("On a populated secret", func(t *testing.T) {
		variableIdentifier := "existent-variable-with-defined-value"

		oldSecretValue := fmt.Sprintf("old-secret-value-%v", rand.Intn(123456))
		secretValue := fmt.Sprintf("latest-secret-value-%v", rand.Intn(123456))

		policy := fmt.Sprintf(`
- !variable %s
`, variableIdentifier)

		assert.NoError(t, err)

		conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		err = conjur.AddSecret(utils.PolicyBranch()+"/"+variableIdentifier, oldSecretValue)
		assert.NoError(t, err)

		err = conjur.AddSecret(utils.PolicyBranch()+"/"+variableIdentifier, secretValue)

		t.Run("Returns existent variable's defined value as a stream", func(t *testing.T) {
			secretResponse, err := conjur.RetrieveSecretReader(utils.PolicyBranch() + "/" + variableIdentifier)
			assert.NoError(t, err)

			obtainedSecretValue, err := ReadResponseBody(secretResponse)
			assert.NoError(t, err)

			assert.Equal(t, secretValue, string(obtainedSecretValue))
		})

		t.Run("Returns existent variable's defined value", func(t *testing.T) {
			obtainedSecretValue, err := conjur.RetrieveSecret(utils.IDWithPath(variableIdentifier))
			assert.NoError(t, err)

			assert.Equal(t, secretValue, string(obtainedSecretValue))
		})

		t.Run("Handles a fully qualified variable id", func(t *testing.T) {
			obtainedSecretValue, err := conjur.RetrieveSecret("conjur:variable:" + utils.IDWithPath(variableIdentifier))
			assert.NoError(t, err)

			assert.Equal(t, secretValue, string(obtainedSecretValue))
		})

		t.Run("Prepends the account name automatically", func(t *testing.T) {
			obtainedSecretValue, err := conjur.RetrieveSecret("variable:" + utils.IDWithPath(variableIdentifier))
			assert.NoError(t, err)

			assert.Equal(t, secretValue, string(obtainedSecretValue))
		})

		t.Run("Returns correct variable when version specified", func(t *testing.T) {
			obtainedSecretValue, err := conjur.RetrieveSecretWithVersion(utils.IDWithPath(variableIdentifier), 1)
			assert.NoError(t, err)

			assert.Equal(t, oldSecretValue, string(obtainedSecretValue))
		})

		t.Run("Returns correct variable value when version specified defined as a stream", func(t *testing.T) {
			secretResponse, err := conjur.RetrieveSecretWithVersionReader(utils.IDWithPath(variableIdentifier), 1)
			assert.NoError(t, err)

			obtainedSecretValue, err := ReadResponseBody(secretResponse)
			assert.NoError(t, err)

			assert.Equal(t, oldSecretValue, string(obtainedSecretValue))
		})

		t.Run("Rejects an id from the wrong account", func(t *testing.T) {
			_, err := conjur.RetrieveSecret("foobar:variable:" + utils.IDWithPath(variableIdentifier))

			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 404, conjurError.Code)
		})

		t.Run("Rejects an id with the wrong kind", func(t *testing.T) {
			_, err := conjur.RetrieveSecret("conjur:waffle:" + utils.IDWithPath(variableIdentifier))

			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 404, conjurError.Code)
		})
	})

	t.Run("On many populated secrets", func(t *testing.T) {
		variables := map[string]string{
			"myapp-01":             "these",
			"alice@devops":         "are",
			"prod/aws/db-password": "all",
			"research+development": "secret",
			"sales&marketing":      "strings!",
			"onemore":              "{\"json\": \"object\"}",
			"a/ b /c":              "somevalue",
		}
		binaryVariables := map[string]string{
			"binary1":   "test\xf0\xf1",
			"binary2":   "tes\xf0t\xf1i\xf2ng",
			"nonBinary": "testing",
		}

		policy := ""
		for id := range variables {
			policy = fmt.Sprintf("%s- !variable %s\n", policy, id)
		}

		for id := range binaryVariables {
			policy = fmt.Sprintf("%s- !variable %s\n", policy, id)
		}

		conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		for id, value := range variables {
			err = conjur.AddSecret(utils.IDWithPath(id), value)
			assert.NoError(t, err)
		}

		for id, value := range binaryVariables {
			err = conjur.AddSecret(utils.IDWithPath(id), value)
			assert.NoError(t, err)
		}

		t.Run("Fetch many secrets in a single batch retrieval", func(t *testing.T) {
			variableIds := []string{}
			for id := range variables {
				variableIds = append(variableIds, utils.IDWithPath(id))
			}

			secrets, err := conjur.RetrieveBatchSecrets(variableIds)
			assert.NoError(t, err)

			for id, value := range variables {
				fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, utils.IDWithPath(id))
				fetchedValue, ok := secrets[fullyQualifiedID]
				assert.True(t, ok)
				assert.Equal(t, value, string(fetchedValue))
			}
		})

		t.Run("Fetch binary secrets in a batch request", func(t *testing.T) {
			variableIds := []string{}
			for id := range binaryVariables {
				variableIds = append(variableIds, utils.IDWithPath(id))
			}

			secrets, err := conjur.RetrieveBatchSecretsSafe(variableIds)
			assert.NoError(t, err)

			for id, value := range binaryVariables {
				fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, utils.IDWithPath(id))
				fetchedValue, ok := secrets[fullyQualifiedID]
				assert.True(t, ok)
				assert.Equal(t, value, string(fetchedValue))
			}
		})

		t.Run("Fail to fetch binary secrets in batch request", func(t *testing.T) {
			variableIds := []string{}
			for id := range binaryVariables {
				variableIds = append(variableIds, utils.IDWithPath(id))
			}

			_, err := conjur.RetrieveBatchSecrets(variableIds)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Issue encoding secret into JSON format")
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 406, conjurError.Code)
		})
	})

	t.Run("Returns 404 on existent variable with undefined value", func(t *testing.T) {
		variableIdentifier := "existent-variable-with-undefined-value"
		policy := fmt.Sprintf(`
				- !variable %s
				`, variableIdentifier)

		conjur.LoadPolicy(
			PolicyModePut,
			utils.PolicyBranch(),
			strings.NewReader(policy),
		)

		_, err = conjur.RetrieveSecret(utils.IDWithPath(variableIdentifier))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CONJ00076E Variable conjur:variable:data/test/existent-variable-with-undefined-value is empty or not found")
		conjurError := err.(*response.ConjurError)
		assert.Equal(t, 404, conjurError.Code)
		assert.Equal(t, "not_found", conjurError.Details.Code)
	})

	t.Run("Returns 404 on non-existent variable", func(t *testing.T) {

		_, err = conjur.RetrieveSecret(utils.IDWithPath("non-existent-variable"))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CONJ00076E Variable conjur:variable:data/test/non-existent-variable is empty or not found")
		conjurError := err.(*response.ConjurError)
		assert.Equal(t, 404, conjurError.Code)
		assert.Equal(t, "not_found", conjurError.Details.Code)
	})

	t.Run("Given configuration has invalid login credentials", func(t *testing.T) {
		login := "invalid-user"
		apiKey := "invalid-key"

		t.Run("Returns 401 and a user not found error", func(t *testing.T) {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			_, err = conjur.RetrieveSecret(utils.IDWithPath("existent-or-non-existent-variable"))

			assert.Error(t, err)
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 401, conjurError.Code)
		})
	})
}
