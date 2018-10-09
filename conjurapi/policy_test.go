package conjurapi

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

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

		conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
		So(err, ShouldBeNil)

		randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

		Convey("Successfully load policy", func() {
			username := "alice"
			policy := fmt.Sprintf(`
- !user %s
`, username)

			resp, err := conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			So(resp.Version, ShouldBeGreaterThanOrEqualTo, 1)
		})

		Convey("A new role is reported in the policy load response", func() {
			const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
			result := make([]byte, 12)
			for i := range result {
				result[i] = chars[randomizer.Intn(len(chars))]
			}

			username := string(result)
			policy := fmt.Sprintf(`
- !user %s
`, username)

			resp, err := conjur.LoadPolicy(
				PolicyModePut,
				"root",
				strings.NewReader(policy),
			)

			So(err, ShouldBeNil)
			createdRole, ok := resp.CreatedRoles["cucumber:user:"+username]
			So(createdRole.ID, ShouldNotBeBlank)
			So(createdRole.APIKey, ShouldNotBeBlank)
			So(ok, ShouldBeTrue)
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

			conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
			So(err, ShouldBeNil)

			Convey("Policy loading is not supported", func() {
				variableIdentifier := "alice"
				policy := fmt.Sprintf(`
- !user %s
`, variableIdentifier)

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
}
