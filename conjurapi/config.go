package conjurapi

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type Config struct {
	Account      string `yaml:"account,omitempty"`
	ApplianceURL string `yaml:"appliance_url,omitempty"`
	NetRCPath    string `yaml:"netrc_path,omitempty"`
	SSLCert      string `yaml:"-"`
	SSLCertPath  string `yaml:"cert_file,omitempty"`
	AuthnType    string `yaml:"authn_type,omitempty"`
	ServiceID    string `yaml:"service_id,omitempty"`
}

func (c *Config) IsHttps() bool {
	return c.SSLCertPath != "" || c.SSLCert != ""
}

func (c *Config) Validate() error {
	errors := []string{}

	if c.ApplianceURL == "" {
		errors = append(errors, "Must specify an ApplianceURL")
	}

	if c.Account == "" {
		errors = append(errors, "Must specify an Account")
	}

	if c.AuthnType == "ldap" && c.ServiceID == "" {
		errors = append(errors, "Must specify a ServiceID when using LDAP")
	}

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
		if c.IsHttps() {
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
	c.AuthnType = mergeValue(c.AuthnType, o.AuthnType)
	c.ServiceID = mergeValue(c.ServiceID, o.ServiceID)
}

func (c *Config) mergeYAML(filename string) error {
	buf, err := ioutil.ReadFile(filename)

	if err != nil {
		logging.ApiLog.Debugf("Failed reading %s, %v\n", filename, err)
		// It is not an error if this file does not exist
		return nil
	}

	aux := struct {
		ConjurVersion string `yaml:"version"`
		Config        `yaml:",inline"`
	}{}

	if err := yaml.Unmarshal(buf, &aux); err != nil {
		logging.ApiLog.Errorf("Parsing error %s: %s\n", filename, err)
		return err
	}

	logging.ApiLog.Debugf("Config from %s: %+v\n", filename, aux.Config)
	c.merge(&aux.Config)

	return nil
}

func (c *Config) mergeEnv() {
	env := Config{
		ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
		SSLCert:      os.Getenv("CONJUR_SSL_CERTIFICATE"),
		SSLCertPath:  os.Getenv("CONJUR_CERT_FILE"),
		Account:      os.Getenv("CONJUR_ACCOUNT"),
		NetRCPath:    os.Getenv("CONJUR_NETRC_PATH"),
		AuthnType:    os.Getenv("CONJUR_AUTHN_TYPE"),
		ServiceID:    os.Getenv("CONJUR_SERVICE_ID"),
	}

	logging.ApiLog.Debugf("Config from environment: %+v\n", env)
	c.merge(&env)
}

func LoadConfig() (Config, error) {
	config := Config{}

	home, err := os.UserHomeDir()
	if err != nil {
		logging.ApiLog.Warningf("Could not detect homedir.")
	}

	// Default to using ~/.netrc, subsequent configuration can
	// override it if the home dir is set.
	if home != "" {
		config = Config{NetRCPath: path.Join(home, ".netrc")}
	}

	err = config.mergeYAML(path.Join(getSystemPath(), "conjur.conf"))
	if err != nil {
		return config, err
	}

	conjurrc := os.Getenv("CONJURRC")
	if conjurrc == "" && home != "" {
		conjurrc = path.Join(home, ".conjurrc")
	}
	if conjurrc != "" {
		config.mergeYAML(conjurrc)
	}

	config.mergeEnv()

	logging.ApiLog.Debugf("Final config: %+v\n", config)
	return config, nil
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
