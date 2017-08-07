package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"fmt"
	"strings"
)

func TestClient_LoadPolicy(t *testing.T) {
	Convey("Given a valid configuration", t, func() {
		config := Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			APIKey:       os.Getenv("CONJUR_API_KEY"),
			ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
			Username:     "admin",
		}

		Convey("Existent and assigned variable is retrieved", func() {
			variable_identifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variable_identifier)

			conjur := NewClient(config)

			resp, err := conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			So(resp, ShouldContainSubstring, `{"created_roles":{"cucumber:user:alice":`)
		})

		Convey("When the configuration has invalid credentials", func() {
			config.Username = "invalid-user"

			Convey("Loading a policy returns 401", func() {
				conjur := NewClient(config)
				secretValue, err := conjur.LoadPolicy("root", strings.NewReader(""))

				So(err, ShouldNotBeNil)
				So(secretValue, ShouldEqual, "")
				So(err.Error(), ShouldContainSubstring, "401")
			})

		})
	})

}
