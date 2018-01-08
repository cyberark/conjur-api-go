package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"fmt"
	"strings"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func TestClient_LoadPolicy(t *testing.T) {
	Convey("V5", t, func() {
		config := &Config{}
		config.mergeEnv()

		api_key := os.Getenv("CONJUR_AUTHN_API_KEY")
		login := os.Getenv("CONJUR_AUTHN_LOGIN")

		Convey("Successfully load policy", func() {
			variable_identifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			resp, err := conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			So(resp["created_roles"], ShouldNotBeNil)
		})

		Convey("Given invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
				So(err, ShouldBeNil)

				resp, err := conjur.LoadPolicy("root", strings.NewReader(""))

				So(err, ShouldNotBeNil)
				So(resp, ShouldBeNil)
				So(err, ShouldHaveSameTypeAs, &response.ConjurError{})
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

		Convey("Policy loading is not supported", func() {
			variable_identifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variable_identifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
			So(err, ShouldBeNil)

			_, err = conjur.LoadPolicy(
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "LoadPolicy is not supported for Conjur V4")
		})
	})
}
