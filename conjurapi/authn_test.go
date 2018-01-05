package conjurapi

import (
  "testing"
  . "github.com/smartystreets/goconvey/convey"
  "os"
  "fmt"
  "strings"
  "github.com/cyberark/conjur-api-go/conjurapi/authn"
)

func TestClient_RotateAPIKey(t *testing.T) {
  Convey("V5", t, func() {
    config := &Config{}
    config.mergeEnv()

    api_key := os.Getenv("CONJUR_AUTHN_API_KEY")
    login := os.Getenv("CONJUR_AUTHN_LOGIN")

    policy := fmt.Sprintf(`
- !user alice
`)

    conjur, err := NewClientFromKey(*config, authn.LoginPair{login, api_key})
    So(err, ShouldBeNil)

    conjur.LoadPolicy(
      "root",
      strings.NewReader(policy),
    )

    Convey("Rotate the API key of a foreign role", func() {
      aliceApiKey, err := conjur.RotateAPIKey("cucumber:user:alice")

      So(err, ShouldBeNil)

      _, err = conjur.Authenticate(authn.LoginPair{"alice", string(aliceApiKey)})
      So(err, ShouldBeNil)
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

    Convey("Rotate the API key of a foreign role", func() {
      aliceApiKey, err := conjur.RotateAPIKey("cucumber:user:alice")

      So(err, ShouldBeNil)

      _, err = conjur.Authenticate(authn.LoginPair{"alice", string(aliceApiKey)})
      So(err, ShouldBeNil)
    })
  })  
}
