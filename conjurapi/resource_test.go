package conjurapi

import (
  "testing"
  . "github.com/smartystreets/goconvey/convey"
  "os"
  "fmt"
  "strings"
  "github.com/cyberark/conjur-api-go/conjurapi/authn"
)

func TestClient_CheckPermission(t *testing.T) {
  Convey("V5", t, func() {
    config := &Config{}
    config.mergeEnv()

    api_key := os.Getenv("CONJUR_AUTHN_API_KEY")
    login := os.Getenv("CONJUR_AUTHN_LOGIN")

    policy := fmt.Sprintf(`
- !user alice

- !variable db-password

- !permit
  role: !user alice
  privilege: [ execute ]
  resource: !variable db-password
`)

    conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
    So(err, ShouldBeNil)

    conjur.LoadPolicy(
      "root",
      strings.NewReader(policy),
    )

    Convey("Check an allowed permission", func() {
      allowed, err := conjur.CheckPermission("cucumber:variable:db-password", "execute")

      So(err, ShouldBeNil)
      So(allowed, ShouldEqual, true)
    })

    Convey("Check a permission on a non-existent resource", func() {
      allowed, err := conjur.CheckPermission("cucumber:variable:foobar", "execute")

      So(err, ShouldBeNil)
      So(allowed, ShouldEqual, false)
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

    conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
    So(err, ShouldBeNil)

    Convey("Check an allowed permission", func() {
      allowed, err := conjur.CheckPermission("cucumber:variable:existent-variable-with-defined-value", "execute")

      So(err, ShouldBeNil)
      So(allowed, ShouldEqual, true)
    })

    Convey("Check a permission on a non-existent resource", func() {
      allowed, err := conjur.CheckPermission("cucumber:variable:foobar", "execute")

      So(err, ShouldBeNil)
      So(allowed, ShouldEqual, false)
    })
  })
}
