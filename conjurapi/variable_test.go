package conjurapi

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_RetrieveSecret(t *testing.T) {
	Convey("V5", t, func() {
		config := &Config{}
		config.mergeEnv()

		login := os.Getenv("CONJUR_AUTHN_LOGIN")
		apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")

		Convey("On a populated secret", func() {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
- !variable %s
`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)
			err = conjur.AddSecret(variableIdentifier, secretValue)
			So(err, ShouldBeNil)

			Convey("Returns existent variable's defined value as a stream", func() {
				secretResponse, err := conjur.RetrieveSecretReader(variableIdentifier)
				So(err, ShouldBeNil)

				obtainedSecretValue, err := ReadResponseBody(secretResponse)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Returns existent variable's defined value", func() {
				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Handles a fully qualified variable id", func() {
				obtainedSecretValue, err := conjur.RetrieveSecret("cucumber:variable:" + variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Prepends the account name automatically", func() {
				obtainedSecretValue, err := conjur.RetrieveSecret("variable:" + variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Rejects an id from the wrong account", func() {
				_, err := conjur.RetrieveSecret("foobar:variable:" + variableIdentifier)

				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 404)
			})

			Convey("Rejects an id with the wrong kind", func() {
				_, err := conjur.RetrieveSecret("cucumber:waffle:" + variableIdentifier)

				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 404)
			})
		})

		Convey("On many populated secrets", func() {
			variables := map[string]string{
				"myapp-01":             "these",
				"alice@devops":         "are",
				"prod/aws/db-password": "all",
				"research+development": "secret",
				"sales&marketing":      "strings!",
				"onemore":              "{\"json\": \"object\"}",
			}

			policy := ""
			for id := range variables {
				policy = fmt.Sprintf("%s- !variable %s\n", policy, id)
			}

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			for id, value := range variables {
				err = conjur.AddSecret(id, value)
				So(err, ShouldBeNil)
			}

			Convey("Fetch many secrets in a single batch retrieval", func() {
				variableIds := []string{}
				for id := range variables {
					variableIds = append(variableIds, id)
				}

				secrets, err := conjur.RetrieveBatchSecrets(variableIds)
				So(err, ShouldBeNil)

				for id, value := range variables {
					fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, id)
					fetchedValue, ok := secrets[fullyQualifiedID]
					So(ok, ShouldBeTrue)
					So(string(fetchedValue), ShouldEqual, value)
				}
			})
		})

		Convey("Token authenticator can be used to fetch a secret", func() {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
  - !variable %s
  `, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)
			conjur.AddSecret(variableIdentifier, secretValue)

			token, err := conjur.authenticator.RefreshToken()
			So(err, ShouldBeNil)

			conjur, err = NewClientFromToken(*config, string(token))

			obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
			So(err, ShouldBeNil)

			So(string(obtainedSecretValue), ShouldEqual, secretValue)
		})

		Convey("Returns 404 on existent variable with undefined value", func() {
			variableIdentifier := "existent-variable-with-undefined-value"
			policy := fmt.Sprintf(`
- !variable %s
`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			_, err = conjur.RetrieveSecret(variableIdentifier)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Requested version does not exist")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			_, err = conjur.RetrieveSecret("non-existent-variable")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Variable 'non-existent-variable' not found in account 'cucumber'")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
				So(err, ShouldBeNil)

				_, err = conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Unauthorized")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 401)
			})
		})
	})

	Convey("V4", t, func() {
		config := &Config{
			ApplianceURL: os.Getenv("CONJUR_V4_APPLIANCE_URL"),
			SSLCert:      os.Getenv("CONJUR_V4_SSL_CERTIFICATE"),
			Account:      os.Getenv("CONJUR_V4_ACCOUNT"),
			V4:           true,
		}

		login := os.Getenv("CONJUR_V4_AUTHN_LOGIN")
		apiKey := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

		Convey("Returns existent variable's defined value, given full qualified ID", func() {
			variableIdentifier := "cucumber:variable:existent-variable-with-defined-value"
			secretValue := "existent-variable-defined-value"

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
			So(err, ShouldBeNil)

			So(string(obtainedSecretValue), ShouldEqual, secretValue)
		})

		Convey("Returns existent variable's defined value", func() {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := "existent-variable-defined-value"

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
			So(err, ShouldBeNil)

			So(string(obtainedSecretValue), ShouldEqual, secretValue)
		})

		Convey("Returns 404 on existent variable with undefined value", func() {
			variableIdentifier := "existent-variable-with-undefined-value"

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			_, err = conjur.RetrieveSecret(variableIdentifier)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Not Found")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			_, err = conjur.RetrieveSecret("non-existent-variable")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "variable 'non-existent-variable' not found")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
		})

		Convey("Fetch many secrets in a single batch retrieval", func() {
			variables := map[string]string{
				"myapp-01":             "these",
				"alice@devops":         "are",
				"prod/aws/db-password": "all",
				"research+development": "secret",
				"sales&marketing":      "strings",
				"onemore":              "{\"json\": \"object\"}",
			}

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			variableIds := []string{}
			for id := range variables {
				variableIds = append(variableIds, id)
			}
			secrets, err := conjur.RetrieveBatchSecrets(variableIds)
			So(err, ShouldBeNil)

			for id, value := range variables {
				fetchedValue, ok := secrets[id]
				So(ok, ShouldBeTrue)
				So(string(fetchedValue), ShouldEqual, value)
			}
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
				So(err, ShouldBeNil)

				_, err = conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Unauthorized")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 401)
			})
		})
	})
}
