package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"io/ioutil"
)

func TestClient_getAuthToken(t *testing.T) {
	Convey("Given a valid configuration", t, func() {
		config := Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
		}

		Convey("Given no authentication information", func() {
			Convey("Return with error containing failed validations", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				tokenBytes, err := conjur.getAuthToken()

				So(err.Error(), ShouldContainSubstring, "Missing")
				So(tokenBytes, ShouldBeNil)
			})
		})

		Convey("Given valid Login credentials", func() {
			config.APIKey =	os.Getenv("CONJUR_AUTHN_API_KEY")
			config.Username = "admin"

			Convey("Returns token bytes", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				tokenBytes, err := conjur.getAuthToken()

				So(err, ShouldBeNil)
				So(tokenBytes, ShouldNotBeNil)
			})

			Convey("Given non-existent username", func() {
				config.Username = "non-existent-username"
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				Convey("Returns nil token and 401 error", func() {
					_, err := conjur.getAuthToken()
					So(err.Error(), ShouldContainSubstring, "401")
				})
			})
		})

		Convey("Given existent token filename and valid Login credentials", func() {
			config.AuthnTokenFile =	"/tmp/valid-token-file"
			config.APIKey =	os.Getenv("CONJUR_AUTHN_API_KEY")
			config.Username = "admin"

			os.Remove("/tmp/valid-token-file")
			go func() {
				ioutil.WriteFile("/tmp/valid-token-file", []byte("token-from-file"), 0644)
			}()
			defer os.Remove("/tmp/valid-token-file")

			Convey("Return the token from the file (token filename takes precedence over Login credentials)", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				tokenBytes, err := conjur.getAuthToken()

				So(err, ShouldBeNil)
				So(string(tokenBytes), ShouldEqual, "token-from-file")
			})
		})

	})
}
