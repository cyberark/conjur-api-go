package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
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

func TestLoadFromEnv(t *testing.T) {
	Convey("Given configuration and authentication credentials in env", t, func() {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")

		Convey("Returns Config loaded with values from env", func() {
			config := &Config{}
			LoadFromEnv(config)

			So(*config, ShouldResemble, Config{
				Account: "account",
				ApplianceURL: "appliance-url",
			})
		})
	})
}