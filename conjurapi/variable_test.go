package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"fmt"
	"math/rand"
	"strings"
)

func TestClient_RetrieveSecret(t *testing.T) {
	Convey("Given valid configuration and login credentials", t, func() {
		config := &Config{}
		config.mergeEnv()

		login := os.Getenv("CONJUR_AUTHN_LOGIN")
		api_key := os.Getenv("CONJUR_AUTHN_API_KEY")

		Convey("Returns existent variable's defined value", func() {
			variable_identifier := "existent-var-with-defined-value"
			secret_value := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
- !variable %s
`, variable_identifier)


			conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)
			conjur.AddSecret(variable_identifier, secret_value)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldBeNil)
			So(secretValue, ShouldEqual, secret_value)
		})

		Convey("Returns 404 on existent variable with undefined value", func() {
			variable_identifier := "existent-value-with-undefined-value"
			policy := fmt.Sprintf(`
- !variable %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
			So(err, ShouldBeNil)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldNotBeNil)
			So(secretValue, ShouldEqual, "")
			So(err.Error(), ShouldContainSubstring, "404")
		})

		Convey("Returns 404 on non-existent variable", func() {
			conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
			So(err, ShouldBeNil)

			secretValue, err := conjur.RetrieveSecret("not-existent-variable")

			So(err, ShouldNotBeNil)
			So(secretValue, ShouldEqual, "")
			So(err.Error(), ShouldContainSubstring, "404")
		})

		Convey("Given configuration has invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
				So(err, ShouldBeNil)

				secretValue, err := conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(secretValue, ShouldEqual, "")
				So(err.Error(), ShouldContainSubstring, "401")
			})

		})
	})

}
