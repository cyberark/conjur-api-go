package conjurapi

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"testing"
)

func TempFileForTesting(prefix string, fileContents string) (string, error) {
	tmpfile, err := ioutil.TempFile(os.TempDir(), prefix)
	if err != nil {
		return "", err
	}

	if _, err := tmpfile.Write([]byte(fileContents)); err != nil {
		return "", err
	}
	if err := tmpfile.Close(); err != nil {
		return "", err
	}

	return tmpfile.Name(), err
}

func TestConfig_IsValid(t *testing.T) {
	Convey("Return without error for valid configuration", t, func() {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
		}

		err := config.validate()

		So(err, ShouldBeNil)
	})

	Convey("Return error for invalid configuration", t, func() {
		config := Config{
			Account: "account",
		}

		err := config.validate()
		So(err, ShouldNotBeNil)

		errString := err.Error()

		So(errString, ShouldContainSubstring, "Must specify an ApplianceURL")
	})
}

func TestConfig_IsHttps(t *testing.T) {
	Convey("Return true for configuration with SSLCert", t, func() {
		config := Config{
			SSLCert: "cert",
		}

		err := config.IsHttps()

		So(err, ShouldBeTrue)
	})

	Convey("Return true for configuration with SSLCertPath", t, func() {
		config := Config{
			SSLCertPath: "path/to/cert",
		}

		err := config.IsHttps()

		So(err, ShouldBeTrue)
	})

	Convey("Return false for configuration without SSLCert or SSLCertPath", t, func() {
		config := Config{
		}

		err := config.IsHttps()

		So(err, ShouldBeFalse)
	})

}

func TestConfig_LoadFromEnv(t *testing.T) {
	Convey("Given configuration and authentication credentials in env", t, func() {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")

		Convey("Returns Config loaded with values from env", func() {
			config := &Config{}
			config.mergeEnv()

			So(*config, ShouldResemble, Config{
				Account:      "account",
				ApplianceURL: "appliance-url",
			})
		})
	})
}

var versiontests = []struct {
	in    string
	label string
	out   bool
}{
	{"version: 4", "version 4", true},
	{"version: 5", "version 5", false},
	{"", "empty version", false},
}

func TestConfig_mergeYAML(t *testing.T) {
	Convey("No other netrc specified", t, func() {
		usr, err := user.Current()
		if err != nil {
			return
		}

		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")

		Convey("Uses $HOME/.netrc by deafult", func() {
			config, err := LoadConfig()
			So(err, ShouldBeNil)

			So(config, ShouldResemble, Config{
				Account:      "account",
				ApplianceURL: "appliance-url",
				NetRCPath:    path.Join(usr.HomeDir, ".netrc"),
			})
		})
	})

	for index, versiontest := range versiontests {
		Convey(fmt.Sprintf("Given a filled conjurrc file with %s", versiontest.label), t, func() {
			conjurrcFileContents := fmt.Sprintf(`
---
appliance_url: http://path/to/appliance%v
account: some account%v
cert_file: "/path/to/cert/file/pem%v"
netrc_path: "/path/to/netrc/file%v"
%s
`, index, index, index, index, versiontest.in)

			tmpFileName, err := TempFileForTesting("TestConfigVersion", conjurrcFileContents)
			defer os.Remove(tmpFileName) // clean up
			So(err, ShouldBeNil)

			Convey(fmt.Sprintf("Returns Config loaded with values from file and V4: %t", versiontest.out), func() {
				config := &Config{}
				config.mergeYAML(tmpFileName)

				So(*config, ShouldResemble, Config{
					Account:      fmt.Sprintf("some account%v", index),
					ApplianceURL: fmt.Sprintf("http://path/to/appliance%v", index),
					NetRCPath:    fmt.Sprintf("/path/to/netrc/file%v", index),
					SSLCertPath:  fmt.Sprintf("/path/to/cert/file/pem%v", index),
					V4:           versiontest.out,
				})
			})
		})
	}
}
