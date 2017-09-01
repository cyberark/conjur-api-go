package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"fmt"
	"strings"
)

func TestClient_LoadPolicy(t *testing.T) {
	Convey("Given valid configuration and login credentials", t, func() {
		config := &Config{}
		config.mergeEnv()

		api_key := os.Getenv("CONJUR_AUTHN_API_KEY")
		login := os.Getenv("CONJUR_AUTHN_LOGIN")

		Convey("Successfully load policy", func() {
			variable_identifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
			So(err, ShouldBeNil)

			resp, err := conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			So(resp, ShouldContainSubstring, `{"created_roles":{"cucumber:user:alice":`)
		})

		Convey("Given invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, LoginPair{login, api_key})
				So(err, ShouldBeNil)

				secretValue, err := conjur.LoadPolicy("root", strings.NewReader(""))

				So(err, ShouldNotBeNil)
				So(secretValue, ShouldEqual, "")
				So(err.Error(), ShouldContainSubstring, "401")
			})

		})
	})

}
