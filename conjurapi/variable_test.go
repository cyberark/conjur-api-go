package conjurapi

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
)

func TestClient_RetrieveSecret(t *testing.T) {
	t.Run("V5", func(t *testing.T) {
		config := &Config{}
		config.mergeEnv()

		login := os.Getenv("CONJUR_AUTHN_LOGIN")
		apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")

		t.Run("On a populated secret", func(t *testing.T) {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
- !variable %s
`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)
			err = conjur.AddSecret(variableIdentifier, secretValue)
			assert.NoError(t, err)

			t.Run("Returns existent variable's defined value as a stream", func(t *testing.T) {
				secretResponse, err := conjur.RetrieveSecretReader(variableIdentifier)
				assert.NoError(t, err)

				obtainedSecretValue, err := ReadResponseBody(secretResponse)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Returns existent variable's defined value", func(t *testing.T) {
				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Handles a fully qualified variable id", func(t *testing.T) {
				obtainedSecretValue, err := conjur.RetrieveSecret("cucumber:variable:" + variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Prepends the account name automatically", func(t *testing.T) {
				obtainedSecretValue, err := conjur.RetrieveSecret("variable:" + variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Rejects an id from the wrong account", func(t *testing.T) {
				_, err := conjur.RetrieveSecret("foobar:variable:" + variableIdentifier)

				conjurError := err.(*response.ConjurError)
				assert.Equal(t, 404, conjurError.Code)
			})

			t.Run("Rejects an id with the wrong kind", func(t *testing.T) {
				_, err := conjur.RetrieveSecret("cucumber:waffle:" + variableIdentifier)

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

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			for id, value := range variables {
				err = conjur.AddSecret(id, value)
				assert.NoError(t, err)
			}

			for id, value := range binaryVariables {
				err = conjur.AddSecret(id, value)
				assert.NoError(t, err)
			}

			t.Run("Fetch many secrets in a single batch retrieval", func(t *testing.T) {
				variableIds := []string{}
				for id := range variables {
					variableIds = append(variableIds, id)
				}

				secrets, err := conjur.RetrieveBatchSecrets(variableIds)
				assert.NoError(t, err)

				for id, value := range variables {
					fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, id)
					fetchedValue, ok := secrets[fullyQualifiedID]
					assert.True(t, ok)
					assert.Equal(t, value, string(fetchedValue))
				}
			})

			t.Run("Fetch binary secrets in a batch request", func(t *testing.T) {
				variableIds := []string{}
				for id := range binaryVariables {
					variableIds = append(variableIds, id)
				}

				secrets, err := conjur.RetrieveBatchSecretsSafe(variableIds)
				assert.NoError(t, err)

				for id, value := range binaryVariables {
					fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, id)
					fetchedValue, ok := secrets[fullyQualifiedID]
					assert.True(t, ok)
					assert.Equal(t, value, string(fetchedValue))
				}
			})

			t.Run("Fail to fetch binary secrets in batch request", func(t *testing.T) {
				variableIds := []string{}
				for id := range binaryVariables {
					variableIds = append(variableIds, id)
				}

				_, err := conjur.RetrieveBatchSecrets(variableIds)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Issue encoding secret into JSON format")
				conjurError := err.(*response.ConjurError)
				assert.Equal(t, 406, conjurError.Code)
			})
		})

		t.Run("Token authenticator can be used to fetch a secret", func(t *testing.T) {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
  - !variable %s
  `, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)
			conjur.AddSecret(variableIdentifier, secretValue)

			token, err := conjur.authenticator.RefreshToken()
			assert.NoError(t, err)

			conjur, err = NewClientFromToken(*config, string(token))
			assert.NoError(t, err)

			obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
			assert.NoError(t, err)
			assert.Equal(t, secretValue, string(obtainedSecretValue))
		})

		t.Run("Returns 404 on existent variable with undefined value", func(t *testing.T) {
			variableIdentifier := "existent-variable-with-undefined-value"
			policy := fmt.Sprintf(`
				- !variable %s
				`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			_, err = conjur.RetrieveSecret(variableIdentifier)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "CONJ00076E Variable cucumber:variable:existent-variable-with-undefined-value is empty or not found")
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 404, conjurError.Code)
			assert.Equal(t, "not_found", conjurError.Details.Code)
		})

		t.Run("Returns 404 on non-existent variable", func(t *testing.T) {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			assert.NoError(t, err)

			_, err = conjur.RetrieveSecret("non-existent-variable")

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "CONJ00076E Variable cucumber:variable:non-existent-variable is empty or not found")
			conjurError := err.(*response.ConjurError)
			assert.Equal(t, 404, conjurError.Code)
			assert.Equal(t, "not_found", conjurError.Details.Code)
		})

		t.Run("Given configuration has invalid login credentials", func(t *testing.T) {
			login = "invalid-user"

			t.Run("Returns 401", func(t *testing.T) {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				_, err = conjur.RetrieveSecret("existent-or-non-existent-variable")

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Unauthorized")
				conjurError := err.(*response.ConjurError)
				assert.Equal(t, 401, conjurError.Code)
			})
		})
	})

	if os.Getenv("TEST_VERSION") != "oss" {
		t.Run("V4", func(t *testing.T) {
			config := &Config{
				ApplianceURL: os.Getenv("CONJUR_V4_APPLIANCE_URL"),
				SSLCert:      os.Getenv("CONJUR_V4_SSL_CERTIFICATE"),
				Account:      os.Getenv("CONJUR_V4_ACCOUNT"),
				V4:           true,
			}

			login := os.Getenv("CONJUR_V4_AUTHN_LOGIN")
			apiKey := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

			t.Run("Returns existent variable's defined value, given full qualified ID", func(t *testing.T) {
				variableIdentifier := "cucumber:variable:existent-variable-with-defined-value"
				secretValue := "existent-variable-defined-value"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Returns existent variable's defined value", func(t *testing.T) {
				variableIdentifier := "existent-variable-with-defined-value"
				secretValue := "existent-variable-defined-value"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Returns space-pathed existent variable's defined value", func(t *testing.T) {
				variableIdentifier := "a/ b/c"
				secretValue := "a/ b/c"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				assert.NoError(t, err)

				assert.Equal(t, secretValue, string(obtainedSecretValue))
			})

			t.Run("Returns 404 on existent variable with undefined value", func(t *testing.T) {
				variableIdentifier := "existent-variable-with-undefined-value"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				_, err = conjur.RetrieveSecret(variableIdentifier)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Not Found")
				conjurError := err.(*response.ConjurError)
				assert.Equal(t, 404, conjurError.Code)
			})

			t.Run("Returns 404 on non-existent variable", func(t *testing.T) {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				_, err = conjur.RetrieveSecret("non-existent-variable")

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "variable 'non-existent-variable' not found")
				conjurError := err.(*response.ConjurError)
				assert.Equal(t, 404, conjurError.Code)
			})

			t.Run("Fetch many secrets in a single batch retrieval", func(t *testing.T) {
				variables := map[string]string{
					"myapp-01":             "these",
					"alice@devops":         "are",
					"prod/aws/db-password": "all",
					"research+development": "secret",
					"sales&marketing":      "strings",
					"onemore":              "{\"json\": \"object\"}",
				}

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				assert.NoError(t, err)

				variableIds := []string{}
				for id := range variables {
					variableIds = append(variableIds, id)
				}

				secrets, err := conjur.RetrieveBatchSecrets(variableIds)
				assert.NoError(t, err)

				for id, value := range variables {
					fetchedValue, ok := secrets[id]
					assert.True(t, ok)
					assert.Equal(t, value, string(fetchedValue))
				}

				t.Run("Fail to use the safe method for batch retrieval", func(t *testing.T) {
					_, err := conjur.RetrieveBatchSecretsSafe(variableIds)
					assert.Contains(t, err.Error(), "not supported in Conjur V4")
				})

				t.Run("Fail to retrieve binary secret in batch retrieval", func(t *testing.T) {
					variableIds = append(variableIds, "binary")

					_, err := conjur.RetrieveBatchSecrets(variableIds)
					conjurError := err.(*response.ConjurError)
					assert.Equal(t, 500, conjurError.Code)
				})
			})

			t.Run("Given configuration has invalid login credentials", func(t *testing.T) {
				login = "invalid-user"

				t.Run("Returns 401", func(t *testing.T) {
					conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
					assert.NoError(t, err)

					_, err = conjur.RetrieveSecret("existent-or-non-existent-variable")

					assert.Error(t, err)
					assert.Contains(t, err.Error(), "Unauthorized")
					conjurError := err.(*response.ConjurError)
					assert.Equal(t, 401, conjurError.Code)
				})
			})
		})
	}
}
