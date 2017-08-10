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
	Convey("Given a valid configuration", t, func() {
		config := Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			APIKey:       os.Getenv("CONJUR_API_KEY"),
			ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
			Username:     "admin",
		}

		Convey("Existent and assigned variable is retrieved", func() {
			variable_identifier := "db/password"
			secret_value := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			policy := fmt.Sprintf(`
- !variable %s
`, variable_identifier)


			conjur := NewClient(config)

			conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)
			conjur.AddSecret(variable_identifier, secret_value)

			secretValue, err := conjur.RetrieveSecret(variable_identifier)

			So(err, ShouldBeNil)
			So(secretValue, ShouldEqual, secret_value)
		})

		Convey("Fetching a secret on a non-existent variable returns 404", func() {
			conjur := NewClient(config)
			secretValue, err := conjur.RetrieveSecret("not-existent-variable")

			So(err, ShouldNotBeNil)
			So(secretValue, ShouldEqual, "")
			So(err.Error(), ShouldContainSubstring, "404")
		})

		Convey("When the configuration has invalid credentials", func() {
			config.Username = "invalid-user"

			Convey("Secret fetching returns 401", func() {
				conjur := NewClient(config)
				secretValue, err := conjur.RetrieveSecret("existent-or-non-existent-variable")

				So(err, ShouldNotBeNil)
				So(secretValue, ShouldEqual, "")
				So(err.Error(), ShouldContainSubstring, "401")
			})

		})
	})

}
