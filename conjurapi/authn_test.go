package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_RotateAPIKey(t *testing.T) {
	Convey("V5", t, func() {
		config := &Config{}
		config.mergeEnv()

		apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
		login := os.Getenv("CONJUR_AUTHN_LOGIN")

		policy := fmt.Sprintf(`
- !user alice
`)

		conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
		So(err, ShouldBeNil)

		conjur.LoadPolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)

		Convey("Rotate the API key of a foreign role", func() {
			aliceAPIKey, err := conjur.RotateAPIKey("cucumber:user:alice")

			_, err = conjur.Authenticate(authn.LoginPair{"alice", string(aliceAPIKey)})
			So(err, ShouldBeNil)
		})

		Convey("Rotate the API key of a foreign role and read the data stream", func() {
			rotateResponse, err := conjur.RotateAPIKeyReader("cucumber:user:alice")

			So(err, ShouldBeNil)
			aliceAPIKey, err := ReadResponseBody(rotateResponse)
			So(err, ShouldBeNil)

			_, err = conjur.Authenticate(authn.LoginPair{"alice", string(aliceAPIKey)})
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
		apiKey := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

		conjur, err := NewClientFromKey(*config, authn.LoginPair{login, apiKey})
		So(err, ShouldBeNil)

		Convey("Rotate the API key of a foreign role", func() {
			aliceAPIKey, err := conjur.RotateAPIKey("cucumber:user:alice")

			_, err = conjur.Authenticate(authn.LoginPair{"alice", string(aliceAPIKey)})
			So(err, ShouldBeNil)
		})
	})
}
