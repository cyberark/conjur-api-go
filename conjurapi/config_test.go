package conjurapi

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TempFileForTesting(prefix string, fileContents string, t *testing.T) (string, error) {
	tmpfile, err := os.CreateTemp(t.TempDir(), prefix)
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

func TestConfig_Validate(t *testing.T) {
	t.Run("Return without error for valid configuration", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Return error for invalid configuration missing ApplianceURL", func(t *testing.T) {
		config := Config{
			Account: "account",
		}

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "Must specify an ApplianceURL")
	})

	t.Run("Return error for authn-ldap configuration missing ServiceId", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
			AuthnType:    "ldap",
		}

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "Must specify a ServiceID when using ldap")
	})

	t.Run("Return error for authn-oidc configuration missing ServiceId", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
			AuthnType:    "oidc",
		}

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "Must specify a ServiceID when using oidc")
	})

	t.Run("Return error for invalid configuration unsupported AuthnType", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
			AuthnType:    "foobar",
			ServiceID:    "service-id",
		}

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "AuthnType must be one of ")
	})

	t.Run("Return error for invalid configuration missing JWT", func(t *testing.T) {
		config := Config{
			Account:      "account",
			ApplianceURL: "appliance-url",
			AuthnType:    "jwt",
			ServiceID:    "service-id",
		}

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "Must specify a JWT token when using JWT authentication")
	})

	t.Run("Includes config when debug logging is enabled", func(t *testing.T) {
		config := Config{
			Account: "account",
		}
		logLevel := logging.ApiLog.Level
		logging.ApiLog.SetLevel(logrus.DebugLevel)
		// Reset log level after test
		defer logging.ApiLog.SetLevel(logLevel)

		err := config.Validate()
		assert.Error(t, err)

		errString := err.Error()
		assert.Contains(t, errString, "Must specify an ApplianceURL")
		assert.Contains(t, errString, "config: &{Account:account ApplianceURL: ")
	})
}

func TestConfig_IsHttps(t *testing.T) {
	t.Run("Return true for configuration with SSLCert", func(t *testing.T) {
		config := Config{
			SSLCert: "cert",
		}

		isHttps := config.IsHttps()
		assert.True(t, isHttps)
	})

	t.Run("Return true for configuration with SSLCertPath", func(t *testing.T) {
		config := Config{
			SSLCertPath: "path/to/cert",
		}

		isHttps := config.IsHttps()
		assert.True(t, isHttps)
	})

	t.Run("Return false for configuration without SSLCert or SSLCertPath", func(t *testing.T) {
		config := Config{}

		isHttps := config.IsHttps()
		assert.False(t, isHttps)
	})

}

func TestConfig_LoadFromEnv(t *testing.T) {
	t.Run("Given configuration and authentication credentials in env", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")
		os.Setenv("CONJUR_AUTHN_TYPE", "ldap")
		os.Setenv("CONJUR_SERVICE_ID", "service-id")
		os.Setenv("CONJUR_CREDENTIAL_STORAGE", "keyring")

		t.Run("Returns Config loaded with values from env", func(t *testing.T) {
			config := &Config{}
			config.mergeEnv()

			assert.EqualValues(t, *config, Config{
				Account:           "account",
				ApplianceURL:      "appliance-url",
				AuthnType:         "ldap",
				ServiceID:         "service-id",
				CredentialStorage: "keyring",
			})
		})
	})

	t.Run("When CONJUR_AUTHN_JWT_SERVICE_ID is set", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")
		os.Setenv("CONJUR_AUTHN_JWT_SERVICE_ID", "jwt-service-id")

		t.Run("Defaults AuthnType to jwt", func(t *testing.T) {
			config := &Config{}
			config.mergeEnv()

			assert.EqualValues(t, *config, Config{
				Account:      "account",
				ApplianceURL: "appliance-url",
				AuthnType:    "jwt",
				ServiceID:    "jwt-service-id",
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
	t.Run("No other netrc specified", func(t *testing.T) {
		home := os.Getenv("HOME")
		assert.NotEmpty(t, home)

		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("HOME", home)
		os.Setenv("CONJUR_ACCOUNT", "account")
		os.Setenv("CONJUR_APPLIANCE_URL", "appliance-url")

		t.Run("Uses $HOME/.netrc by deafult", func(t *testing.T) {
			config, err := LoadConfig()
			assert.NoError(t, err)

			assert.EqualValues(t, config, Config{
				Account:      "account",
				ApplianceURL: "appliance-url",
				NetRCPath:    path.Join(home, ".netrc"),
			})
		})
	})

	t.Run("Defaults Account to 'conjur' with Conjur Cloud ApplianceURL", func(t *testing.T) {
		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJUR_APPLIANCE_URL", "https://test.secretsmgr.cyberark.cloud")

		config, err := LoadConfig()
		assert.NoError(t, err)

		assert.Equal(t, "conjur", config.Account)

		err = config.Validate()
		assert.NoError(t, err)
	})

	for index, versiontest := range versiontests {
		t.Run(fmt.Sprintf("Given a filled conjurrc file with %s", versiontest.label), func(t *testing.T) {
			conjurrcFileContents := fmt.Sprintf(`
---
appliance_url: http://path/to/appliance%v
account: some account%v
cert_file: "/path/to/cert/file/pem%v"
netrc_path: "/path/to/netrc/file%v"
authn_type: ldap
service_id: my-ldap-service
%s
`, index, index, index, index, versiontest.in)

			tmpFileName, err := TempFileForTesting("TestConfigVersion", conjurrcFileContents, t)
			defer os.Remove(tmpFileName) // clean up
			assert.NoError(t, err)

			t.Run(fmt.Sprintf("Returns Config loaded with values from file: %t", versiontest.out), func(t *testing.T) {
				config := &Config{}
				config.mergeYAML(tmpFileName)

				assert.EqualValues(t, *config, Config{
					Account:      fmt.Sprintf("some account%v", index),
					ApplianceURL: fmt.Sprintf("http://path/to/appliance%v", index),
					NetRCPath:    fmt.Sprintf("/path/to/netrc/file%v", index),
					SSLCertPath:  fmt.Sprintf("/path/to/cert/file/pem%v", index),
					AuthnType:    "ldap",
					ServiceID:    "my-ldap-service",
				})
			})
		})
	}

	t.Run("Throws errors when conjurrc is present but unparsable", func(t *testing.T) {
		badConjurrc := `
---
appliance_url: http://path/to/appliance
account: some account
cert_file: "C:\badly\escaped\path"
`

		tmpFileName, err := TempFileForTesting("TestConfigParsingErroHandling", badConjurrc, t)
		defer os.Remove(tmpFileName) // clean up
		assert.NoError(t, err)

		config := &Config{}
		err = config.mergeYAML(tmpFileName)
		assert.Error(t, err)
	})

	t.Run("Values in environment variables override conjurrc file", func(t *testing.T) {
		conjurrcFileContents := `
---
appliance_url: http://path/to/appliance
account: some_account
cert_file: "/path/to/cert/file/pem"
`

		tmpFileName, err := TempFileForTesting("TestConfigEnvOverConjurrc", conjurrcFileContents, t)
		defer os.Remove(tmpFileName) // clean up
		assert.NoError(t, err)

		e := ClearEnv()
		defer e.RestoreEnv()

		os.Setenv("CONJURRC", tmpFileName) // Use the temp file as the conjurrc file
		os.Setenv("CONJUR_ACCOUNT", "env_account")
		os.Setenv("CONJUR_APPLIANCE_URL", "env_appliance_url")

		config, err := LoadConfig()
		assert.NoError(t, err)

		assert.EqualValues(t, config, Config{
			Account:      "env_account",
			ApplianceURL: "env_appliance_url",
			SSLCertPath:  "/path/to/cert/file/pem", // from conjurrc, since not set in env
		})
	})

	// BEGIN COMPATIBILITY WITH PYTHON CLI
	t.Run("Accepts conjur_url and conjur_account for backwards compatibility", func(t *testing.T) {
		conjurrcFileContents := `
---
conjur_url: http://path/to/appliance
conjur_account: some account
`

		tmpFileName, err := TempFileForTesting("TestConfigBackwardsCompatibility", conjurrcFileContents, t)
		defer os.Remove(tmpFileName) // clean up
		assert.NoError(t, err)

		config := &Config{}
		config.mergeYAML(tmpFileName)
		assert.EqualValues(t, *config, Config{
			Account:      "some account",
			ApplianceURL: "http://path/to/appliance",
		})
	})
	// END COMPATIBILITY WITH PYTHON CLI
}

var conjurrcTestCases = []struct {
	name     string
	config   Config
	expected string
}{
	{
		name: "Minimal config",
		config: Config{
			Account:      "test-account",
			ApplianceURL: "test-appliance-url",
		},
		expected: `account: test-account
appliance_url: test-appliance-url
`,
	},
	{
		name: "Full config",
		config: Config{
			Account:           "test-account",
			ApplianceURL:      "test-appliance-url",
			AuthnType:         "oidc",
			ServiceID:         "test-service-id",
			SSLCertPath:       "test-cert-path",
			NetRCPath:         "test-netrc-path",
			SSLCert:           "test-cert",
			CredentialStorage: "keyring",
		},
		expected: `account: test-account
appliance_url: test-appliance-url
netrc_path: test-netrc-path
cert_file: test-cert-path
authn_type: oidc
service_id: test-service-id
credential_storage: keyring
`,
	},
}

func TestConfig_Conjurrc(t *testing.T) {
	t.Run("Generates conjurrc content", func(t *testing.T) {
		for _, testCase := range conjurrcTestCases {
			t.Run(testCase.name, func(t *testing.T) {
				actual := testCase.config.Conjurrc()
				assert.Equal(t, testCase.expected, string(actual))
			})
		}
	})
}

func TestConfig_ReadSSLCert(t *testing.T) {
	t.Parallel()

	t.Run("Reads SSL cert from file", func(t *testing.T) {
		tmpFileName, err := TempFileForTesting("TestConfigReadSSLCert", "test-cert", t)
		defer os.Remove(tmpFileName) // clean up
		assert.NoError(t, err)

		config := Config{
			SSLCertPath: tmpFileName,
		}

		cert, err := config.ReadSSLCert()
		assert.NoError(t, err)
		assert.Equal(t, "test-cert", string(cert))
	})

	t.Run("Returns error when SSL cert file is not found", func(t *testing.T) {
		config := Config{
			SSLCertPath: "not-found",
		}

		_, err := config.ReadSSLCert()
		assert.Error(t, err)
	})

	t.Run("Returns error when SSL cert file is not set", func(t *testing.T) {
		config := Config{}

		cert, err := config.ReadSSLCert()
		assert.EqualError(t, err, "open : no such file or directory")
		assert.Nil(t, cert)
	})

	t.Run("Returns SSLCert when set", func(t *testing.T) {
		config := Config{
			SSLCert: "test-cert",
		}

		cert, err := config.ReadSSLCert()
		assert.NoError(t, err)
		assert.Equal(t, "test-cert", string(cert))
	})
}

func TestConfig_BaseURL(t *testing.T) {
	testCases := []struct {
		name         string
		applianceUrl string
		sslCert      string
		expected     string
	}{
		{
			name:         "with https prefix",
			applianceUrl: "https://conjur.myorg.com",
			expected:     "https://conjur.myorg.com",
		},
		{
			name:         "without prefix",
			applianceUrl: "conjur.myorg.com",
			expected:     "http://conjur.myorg.com",
		},
		{
			name:         "with cert",
			applianceUrl: "conjur.myorg.com",
			sslCert:      "test-cert",
			expected:     "https://conjur.myorg.com",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				ApplianceURL: testCase.applianceUrl,
				SSLCert:      testCase.sslCert,
			}

			actual := config.BaseURL()
			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestConfig_GetHttpTimeout(t *testing.T) {
	testCases := []struct {
		name                string
		configHttpTimeout   int
		expectedHttpTimeout int
	}{
		{
			name:                "smaller than zero",
			configHttpTimeout:   -1,
			expectedHttpTimeout: 0,
		},
		{
			name:                "equal to zero",
			configHttpTimeout:   0,
			expectedHttpTimeout: HttpTimeoutDefaultValue,
		},
		{
			name:                "greater then zero",
			configHttpTimeout:   5,
			expectedHttpTimeout: 5,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				HttpTimeout: testCase.configHttpTimeout,
			}

			assert.Equal(t, testCase.expectedHttpTimeout, config.GetHttpTimeout())
		})
	}
}
