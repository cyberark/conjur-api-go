package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

func TestConfig_IsValid(t *testing.T) {
	Convey("Return without error for valid configuration", t, func() {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
		}

		err := config.validate()

		So(err, ShouldBeNil)
	})

	Convey("Return concatenated error for invalid configuration", t, func() {
		config := Config{
			Account:      "account",
		}

		err := config.validate()
		So(err, ShouldNotBeNil)

		errString := err.Error()

		So(errString, ShouldContainSubstring, "ApplianceURL is required.")
	})
}