package conjurapi

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"runtime"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v1"
)

type Config struct {
	Account      string `yaml:"account"`
	ApplianceURL string `yaml:"appliance_url"`
	NetRCPath    string `yaml:"netrc_path"`
	SSLCert      string
	SSLCertPath  string `yaml:"cert_file"`
	Https        bool
	V4           bool
}

func (c *Config) validate() error {
	errors := []string{}

	if c.ApplianceURL == "" {
		errors = append(errors, "Must specify an ApplianceURL")
	}

	if c.Account == "" {
		errors = append(errors, "Must specify an Account")
	}

	c.Https = c.SSLCertPath != "" || c.SSLCert != ""

	if len(errors) == 0 {
		return nil
	} else if logging.ApiLog.Level == logrus.DebugLevel {
		errors = append(errors, fmt.Sprintf("config: %+v", c))
	}
	return fmt.Errorf("%s", strings.Join(errors, " -- "))
}

func (c *Config) ReadSSLCert() ([]byte, error) {
	if c.SSLCert != "" {
		return []byte(c.SSLCert), nil
	}
	return ioutil.ReadFile(c.SSLCertPath)
}

func (c *Config) BaseURL() string {
	prefix := ""
	if !strings.HasPrefix(c.ApplianceURL, "http") {
		if c.Https {
			prefix = "https://"
		} else {
			prefix = "http://"
		}
	}
	return prefix + c.ApplianceURL
}

func mergeValue(a, b string) string {
	if len(b) != 0 {
		return b
	}
	return a
}

func (c *Config) merge(o *Config) {
	c.ApplianceURL = mergeValue(c.ApplianceURL, o.ApplianceURL)
	c.Account = mergeValue(c.Account, o.Account)
	c.SSLCert = mergeValue(c.SSLCert, o.SSLCert)
	c.SSLCertPath = mergeValue(c.SSLCertPath, o.SSLCertPath)
	c.NetRCPath = mergeValue(c.NetRCPath, o.NetRCPath)
	c.V4 = c.V4 || o.V4
}

func (c *Config) mergeYAML(filename string) {
	buf, err := ioutil.ReadFile(filename)

	if err != nil {
		logging.ApiLog.Debugf("Failed reading %s, %v\n", filename, err)
		return
	}

	aux := struct {
		ConjurVersion string `yaml:"version"`
		Config        `yaml:",inline"`
	}{}
	if err := yaml.Unmarshal(buf, &aux); err != nil {
		return
	}
	aux.Config.V4 = aux.ConjurVersion == "4"

	logging.ApiLog.Debugf("Config from %s: %+v\n", filename, aux.Config)
	c.merge(&aux.Config)
}

func (c *Config) mergeEnv() {
	majorVersion4 := os.Getenv("CONJUR_MAJOR_VERSION") == "4" || os.Getenv("CONJUR_VERSION") == "4"

	env := Config{
		ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
		SSLCert:      os.Getenv("CONJUR_SSL_CERTIFICATE"),
		SSLCertPath:  os.Getenv("CONJUR_CERT_FILE"),
		Account:      os.Getenv("CONJUR_ACCOUNT"),
		NetRCPath:    os.Getenv("CONJUR_NETRC_PATH"),
		V4:           majorVersion4,
	}

	logging.ApiLog.Debugf("Config from environment: %+v\n", env)
	c.merge(&env)
}

func LoadConfig() (config Config, err error) {
	usr, err := user.Current()
	if err != nil {
		return
	}
	// Default to using ~/.netrc, subsequent configuration can
	// override it.
	config = Config{NetRCPath: path.Join(usr.HomeDir, ".netrc")}

	config.mergeYAML(path.Join(getSystemPath(), "conjur.conf"))

	conjurrc := os.Getenv("CONJURRC")
	if conjurrc == "" {
		conjurrc = path.Join(usr.HomeDir, ".conjurrc")
	}
	config.mergeYAML(conjurrc)

	config.mergeEnv()

	logging.ApiLog.Debugf("Final config: %+v\n", config)
	return
}

func getSystemPath() string {
	if runtime.GOOS == "windows" {
		//No way to use SHGetKnownFolderPath()
		//Hardcoding should be fine for now since CONJURRC is available
		return "C:\\windows"
	} else {
		return "/etc"
	}
}
