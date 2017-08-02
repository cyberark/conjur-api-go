package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

func TestIntegerStuff(t *testing.T) {
	Convey("Given some configuration", t, func() {
		config := Config{
			Account:      "test-account",
			APIKey:       "test-api-key",
			ApplianceUrl: "test-appliance-url",
			Username:     "test-username",
		}

		Convey("When an API client is created using the configuration", func() {

			conjur := NewClient(config)

			Convey("The configuration should be accessible as a field on the API instance", func() {
				So(conjur.config, ShouldResemble, config)
			})
		})
	})
}
