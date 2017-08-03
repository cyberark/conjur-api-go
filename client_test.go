package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
)

func TestTokenGeneration(t *testing.T) {
	Convey("Given a valid configuration", t, func() {
		config := Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			APIKey:       os.Getenv("CONJUR_API_KEY"),
			ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
			Username:     "admin",
		}

		Convey("The API client should return a non-empty token", func() {
			conjur := NewClient(config)

			token, err := conjur.getAuthToken()

			So(err, ShouldBeNil)
			So(token, ShouldNotBeBlank)
		})

		Convey("When a non-existent username is configured", func() {
			conjur := NewClient(config)
			conjur.config.Username = "test-username"

			Convey("Token fetching should return a 401 error", func() {
				_, err := conjur.getAuthToken()
				So(err.Error(), ShouldContainSubstring, "401")
			})
		})
	})
}
