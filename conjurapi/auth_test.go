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

		Convey("Given no auth information", func() {
			Convey("The API client should return an error", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				token, err := conjur.getAuthToken()

				So(err.Error(), ShouldContainSubstring, "Missing")
				So(token, ShouldBeBlank)
			})
		})

		Convey("Given valid Login credentials", func() {
			config.APIKey =	os.Getenv("CONJUR_API_KEY")
			config.Username = "admin"

			Convey("The API client should return a non-empty token", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				token, err := conjur.getAuthToken()

				So(err, ShouldBeNil)
				So(token, ShouldNotBeBlank)
			})

			Convey("Set username to non-existent value", func() {
				config.Username = "non-existent-username"
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				Convey("Token fetching should return a 401 error", func() {
					_, err := conjur.getAuthToken()
					So(err.Error(), ShouldContainSubstring, "401")
				})
			})
		})

		Convey("Given existent token filename and valid Login credentials", func() {
			config.AuthnTokenFile =	"/tmp/valid-token-file"
			config.APIKey =	os.Getenv("CONJUR_API_KEY")
			config.Username = "admin"

			os.Remove("/tmp/valid-token-file")
			go func() {
				ioutil.WriteFile("/tmp/valid-token-file", []byte("token-from-file"), 0644)
			}()
			defer os.Remove("/tmp/valid-token-file")

			Convey("The API client should return the token from the file", func() {
				conjur, err := NewClient(config)
				So(err, ShouldBeNil)

				token, err := conjur.getAuthToken()

				So(err, ShouldBeNil)
				So(token, ShouldEqual, "token-from-file")
			})
		})

	})
}
