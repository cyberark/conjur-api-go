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

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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
				"a/ b /c":              "somevalue",
			}
			binaryVariables := map[string]string{
				"binary1":              "test\xf0\xf1",
				"binary2":              "tes\xf0t\xf1i\xf2ng",
				"nonBinary":            "testing",
			}

			policy := ""
			for id := range variables {
				policy = fmt.Sprintf("%s- !variable %s\n", policy, id)
			}

			for id := range binaryVariables {
				policy = fmt.Sprintf("%s- !variable %s\n", policy, id)
			}

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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

			for id, value := range binaryVariables {
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

			Convey("Fetch binary secrets in a batch request", func(){
				variableIds := []string{}
				for id := range binaryVariables {
					variableIds = append(variableIds, id)
				}

				secrets, err := conjur.RetrieveBatchSecretsSafe(variableIds)
				So(err, ShouldBeNil)

				for id, value := range binaryVariables {
					fullyQualifiedID := fmt.Sprintf("%s:variable:%s", config.Account, id)
					fetchedValue, ok := secrets[fullyQualifiedID]
					So(ok, ShouldBeTrue)
					So(string(fetchedValue), ShouldEqual, value)
				}
			})

			Convey("Fail to fetch binary secrets in batch request", func(){
				variableIds := []string{}
				for id := range binaryVariables {
					variableIds = append(variableIds, id)
				}

				_, err := conjur.RetrieveBatchSecrets(variableIds)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Issue encoding secret into JSON format")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 500)
			})
		})

		Convey("Token authenticator can be used to fetch a secret", func() {
			variableIdentifier := "existent-variable-with-defined-value"
			secretValue := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
  - !variable %s
  `, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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

			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			_, err = conjur.RetrieveSecret(variableIdentifier)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "CONJ00076E Variable cucumber:variable:existent-variable-with-undefined-value is empty or not found")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
			So(err, ShouldBeNil)

			_, err = conjur.RetrieveSecret("non-existent-variable")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "CONJ00076E Variable cucumber:variable:non-existent-variable is empty or not found")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				So(err, ShouldBeNil)

				_, err = conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Unauthorized")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 401)
			})
		})
	})

	if os.Getenv("TEST_VERSION") != "oss" {
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

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				So(err, ShouldBeNil)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Returns existent variable's defined value", func() {
				variableIdentifier := "existent-variable-with-defined-value"
				secretValue := "existent-variable-defined-value"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				So(err, ShouldBeNil)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Returns space-pathed existent variable's defined value", func() {
				variableIdentifier := "a/ b/c"
				secretValue := "a/ b/c"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				So(err, ShouldBeNil)

				obtainedSecretValue, err := conjur.RetrieveSecret(variableIdentifier)
				So(err, ShouldBeNil)

				So(string(obtainedSecretValue), ShouldEqual, secretValue)
			})

			Convey("Returns 404 on existent variable with undefined value", func() {
				variableIdentifier := "existent-variable-with-undefined-value"

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
				So(err, ShouldBeNil)

				_, err = conjur.RetrieveSecret(variableIdentifier)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "Not Found")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 404)
			})

			Convey("Returns 404 on non-existent variable", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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

				conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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

				Convey("Fail to use the safe method for batch retrieval", func() {
					_, err := conjur.RetrieveBatchSecretsSafe(variableIds)
					So(err.Error(), ShouldContainSubstring, "not supported in Conjur V4")
				})

				Convey("Fail to retrieve binary secret in batch retrieval", func() {
					variableIds = append(variableIds, "binary")

					_, err := conjur.RetrieveBatchSecrets(variableIds)
					conjurError := err.(*response.ConjurError)
					So(conjurError.Code, ShouldEqual, 500)
				})
			})

			Convey("Given configuration has invalid login credentials", func() {
				login = "invalid-user"

				Convey("Returns 401", func() {
					conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
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
}
