package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_LoadPolicy(t *testing.T) {
	Convey("V5", t, func() {
		config := &Config{}
		config.mergeEnv()

		apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
		login := os.Getenv("CONJUR_AUTHN_LOGIN")

		Convey("Successfully load policy", func() {
			variableIdentifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			resp, err := conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			So(resp["created_roles"], ShouldNotBeNil)
		})

		Convey("Given invalid login credentials", func() {
			login = "invalid-user"

			Convey("Returns 401", func() {
				conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
				So(err, ShouldBeNil)

				resp, err := conjur.LoadPolicy(PolicyModePut, "root", strings.NewReader(""))

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
		apiKey := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

		Convey("Policy loading is not supported", func() {
			variableIdentifier := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, variableIdentifier)

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			_, err = conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "LoadPolicy is not supported for Conjur V4")
		})
	})
}
