package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

func TestConfig_IsValid(t *testing.T) {
	Convey("Should return true and nil for valid configuration", t, func() {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
		}

		valid, err := config.IsValid()

		So(valid, ShouldBeTrue)
		So(err, ShouldBeNil)
	})

	Convey("Should return false and concatenated error for invalid configuration", t, func() {
		config := Config{
			Account:      "account",
		}

		valid, err := config.IsValid()
		So(err, ShouldNotBeNil)

		errString := err.Error()

		So(valid, ShouldBeFalse)
		So(errString, ShouldContainSubstring, "ApplianceURL is required.")
	})
}