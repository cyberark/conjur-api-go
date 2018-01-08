package conjurapi

import (
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	. "github.com/smartystreets/goconvey/convey"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func TestClient_RetrieveSecret(t *testing.T) {
	Convey("V5", t, func() {
		config := &Config{}
		config.mergeEnv()

		login := os.Getenv("CONJUR_AUTHN_LOGIN")
		api_key := os.Getenv("CONJUR_AUTHN_API_KEY")

		Convey("On a populated secret", func() {
			variable_identifier := "existent-variable-with-defined-value"
			secret_value := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
- !variable %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)
			err = conjur.AddSecret(variable_identifier, secret_value)
			So(err, ShouldBeNil)

			Convey("Returns existent variable's defined value", func() {
				secretValue, err := conjur.RetrieveSecret(variable_identifier)

				So(err, ShouldBeNil)
				So(string(secretValue), ShouldEqual, secret_value)
			})

			Convey("Handles a fully qualified variable id", func() {
				secretValue, err := conjur.RetrieveSecret("cucumber:variable:" + variable_identifier)

				So(err, ShouldBeNil)
				So(string(secretValue), ShouldEqual, secret_value)
			})

			Convey("Prepends the account name automatically", func() {
				secretValue, err := conjur.RetrieveSecret("variable:" + variable_identifier)

				So(err, ShouldBeNil)
				So(string(secretValue), ShouldEqual, secret_value)
			})

			Convey("Rejects an id from the wrong account", func() {
				_, err := conjur.RetrieveSecret("foobar:variable:" + variable_identifier)

				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 404)
			})

			Convey("Rejects an id with the wrong kind", func() {
				_, err := conjur.RetrieveSecret("cucumber:waffle:" + variable_identifier)

				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 404)
			})
		})

		Convey("Token authenticator can be used to fetch a secret", func() {
			variable_identifier := "existent-variable-with-defined-value"
			secret_value := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
  - !variable %s
  `, variable_identifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)
			conjur.AddSecret(variable_identifier, secret_value)

			token, err := conjur.authenticator.RefreshToken()
			So(err, ShouldBeNil)

			conjur, err = NewClientFromToken(*config, string(token))

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldBeNil)
			So(string(secretValue), ShouldEqual, secret_value)
		})

		Convey("Returns 404 on existent variable with undefined value", func() {
			variable_identifier := "existent-variable-with-undefined-value"
			policy := fmt.Sprintf(`
- !variable %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldNotBeNil)
			So(string(secretValue), ShouldEqual, "")
			So(err.Error(), ShouldEqual, "Requested version does not exist")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			secretValue, err := conjur.RetrieveSecret("non-existent-variable")

			So(err, ShouldNotBeNil)
			So(string(secretValue), ShouldEqual, "")
			So(err.Error(), ShouldEqual, "Variable 'non-existent-variable' not found in account 'cucumber'")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
			So(conjurError.Details.Code, ShouldEqual, "not_found")
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
				So(err, ShouldBeNil)

				secretValue, err := conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "")
				So(string(secretValue), ShouldEqual, "")
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
		api_key := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

		Convey("Returns existent variable's defined value", func() {
			variable_identifier := "existent-variable-with-defined-value"
			secret_value := "existent-variable-defined-value"

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldBeNil)
			So(string(secretValue), ShouldEqual, secret_value)
		})

		Convey("Returns 404 on existent variable with undefined value", func() {
			variable_identifier := "existent-variable-with-undefined-value"

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldNotBeNil)
			So(string(secretValue), ShouldEqual, "")
			So(err.Error(), ShouldEqual, "")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			secretValue, err := conjur.RetrieveSecret("non-existent-variable")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "variable 'non-existent-variable' not found")
			So(string(secretValue), ShouldEqual, "")
			conjurError := err.(*response.ConjurError)
			So(conjurError.Code, ShouldEqual, 404)
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
				So(err, ShouldBeNil)

				secretValue, err := conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(string(secretValue), ShouldEqual, "")
				So(err.Error(), ShouldEqual, "")
				conjurError := err.(*response.ConjurError)
				So(conjurError.Code, ShouldEqual, 401)
			})
		})
	})
}
