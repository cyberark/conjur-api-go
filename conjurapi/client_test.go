package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewClient(t *testing.T) {
	Convey("Given a valid configuration", t, func() {
		config := Config{
			ApplianceURL: "appliance-url",
			Account: "account",
		}

		Convey("returns a client without error", func() {
			conjur, err := NewClient(config)
			So(err, ShouldBeNil)
			So(conjur, ShouldNotBeNil)
		})

		Convey("Invalidate the configuration", func() {
			config.Account = ""

			Convey("returns nil with error", func() {
				conjur, err := NewClient(config)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "is required.")
				So(conjur, ShouldBeNil)
			})
		})
	})
}
