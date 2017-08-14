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

func TestLoadConfigFromEnv(t *testing.T) {
	Convey("Given configuration and authentication credentials in env", t, func() {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_AUTHN_API_KEY", "authn-api-key")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")
		os.Setenv("CONJUR_AUTHN_LOGIN", "authn-login")
		os.Setenv("CONJUR_AUTHN_TOKEN_FILE", "authn-token-file")

		Convey("Returns Config loaded with values from env", func() {
			config := LoadConfigFromEnv()

			So(config, ShouldResemble, Config{
				Account: "account",
				APIKey: "authn-api-key",
				ApplianceURL: "appliance-url",
				Login: "authn-login",
				AuthnTokenFile: "authn-token-file",
			})
		})
	})
}