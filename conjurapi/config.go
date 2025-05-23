package conjurapi

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"encoding/base64"
	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"path/filepath"
)

const (
	// HTTPTimeoutDefaultValue is the default value for the HTTP client timeout
	HTTPTimeoutDefaultValue = 60
	// HTTPTimeoutMaxValue is the maximum value allowed for the HTTP client timeout
	HTTPTimeoutMaxValue = 600
	// HTTPDailTimeout is the default value for the DialTimeout in the HTTP client
	HTTPDailTimeout = 10

	ConjurSourceHeader = "x-cybr-telemetry"
)

var supportedAuthnTypes = []string{"authn", "ldap", "oidc", "jwt", "iam", "azure", "gcp"}

type Config struct {
	Account            string `yaml:"account,omitempty"`
	ApplianceURL       string `yaml:"appliance_url,omitempty"`
	NetRCPath          string `yaml:"netrc_path,omitempty"`
	SSLCert            string `yaml:"-"`
	SSLCertPath        string `yaml:"cert_file,omitempty"`
	AuthnType          string `yaml:"authn_type,omitempty"`
	ServiceID          string `yaml:"service_id,omitempty"`
	CredentialStorage  string `yaml:"credential_storage,omitempty"`
	JWTHostID          string `yaml:"jwt_host_id,omitempty"`
	JWTContent         string `yaml:"-"`
	JWTFilePath        string `yaml:"jwt_file,omitempty"`
	HTTPTimeout        int    `yaml:"http_timeout,omitempty"`
	IntegrationName    string `yaml:"-"`
	IntegrationType    string `yaml:"-"`
	IntegrationVersion string `yaml:"-"`
	VendorVersion      string `yaml:"-"`
	VendorName         string `yaml:"-"`
	finalTelemetryHeader string `yaml:"-"`
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

	if c.AuthnType != "" && !contains(supportedAuthnTypes, c.AuthnType) {
		errors = append(errors, fmt.Sprintf("AuthnType must be one of %v", supportedAuthnTypes))
	}

	if (c.AuthnType == "ldap" || c.AuthnType == "oidc" || c.AuthnType == "jwt" || c.AuthnType == "iam" || c.AuthnType == "azure") && c.ServiceID == "" {
		errors = append(errors, fmt.Sprintf("Must specify a ServiceID when using %s", c.AuthnType))
	}

	if (c.AuthnType == "jwt" || c.AuthnType == "iam" || c.AuthnType == "azure" || c.AuthnType == "gcp") && (c.JWTContent == "" && c.JWTFilePath == "") {
		errors = append(errors, fmt.Sprintf("Must specify a JWT token when using %s authentication", c.AuthnType))
	}

	if (c.AuthnType == "iam" || c.AuthnType == "azure") && c.JWTHostID == "" {
		errors = append(errors, fmt.Sprintf("Must specify a HostID when using %s authentication", c.AuthnType))
	}

	if c.HTTPTimeout < 0 || c.HTTPTimeout > HTTPTimeoutMaxValue {
		errors = append(errors, fmt.Sprintf("HTTPTimeout must be between 1 and %d seconds", HTTPTimeoutMaxValue))
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
	return os.ReadFile(c.SSLCertPath)
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

// The GetHttpTimeout function retrieves the Timeout value from the config struc.
// If config.HTTPTimeout is
// - less than 0, GetHttpTimeout returns the default value (constant HTTPTimeoutDefaultValue)
// - equal to 0, GetHttpTimeout assumes no value passed and returns the default value (constant HTTPTimeoutDefaultValue)
// - grater than HTTPTimeoutMaxValue, GetHttpTimeout returns the default value (constant HTTPTimeoutDefaultValue)
// Otherwise, GetHttpTimeout returns the value of config.HTTPTimeout
func (c *Config) GetHttpTimeout() int {
	switch {
	case c.HTTPTimeout <= 0:
		return HTTPTimeoutDefaultValue
	case c.HTTPTimeout > HTTPTimeoutMaxValue:
		return HTTPTimeoutDefaultValue
	default:
		return c.HTTPTimeout
	}
}

func mergeValue(a, b string) string {
	if len(b) != 0 {
		return b
	}
	return a
}

func mergeInt(a, b int) int {
	if b != 0 {
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
	c.CredentialStorage = mergeValue(c.CredentialStorage, o.CredentialStorage)
	c.AuthnType = mergeValue(c.AuthnType, o.AuthnType)
	c.ServiceID = mergeValue(c.ServiceID, o.ServiceID)
	c.JWTHostID = mergeValue(c.JWTHostID, o.JWTHostID)
	c.JWTContent = mergeValue(c.JWTContent, o.JWTContent)
	c.JWTFilePath = mergeValue(c.JWTFilePath, o.JWTFilePath)
	c.HTTPTimeout = mergeInt(c.HTTPTimeout, o.HTTPTimeout)
}

func (c *Config) mergeYAML(filename string) error {
	// Read the YAML file
	buf, err := os.ReadFile(filename)

	if err != nil {
		logging.ApiLog.Debugf("Failed reading %s, %v\n", filename, err)
		// It is not an error if this file does not exist
		return nil
	}

	// Parse the YAML file into a new struct containing the same
	// fields as Config, plus a few extra fields for compatibility
	aux := struct {
		ConjurVersion string `yaml:"version"`
		Config        `yaml:",inline"`
		// BEGIN COMPATIBILITY WITH PYTHON CLI
		ConjurURL     string `yaml:"conjur_url"`
		ConjurAccount string `yaml:"conjur_account"`
		// END COMPATIBILITY WITH PYTHON CLI
	}{}

	if err := yaml.Unmarshal(buf, &aux); err != nil {
		logging.ApiLog.Errorf("Parsing error %s: %s\n", filename, err)
		return err
	}

	// Now merge the parsed config into the current config object
	logging.ApiLog.Debugf("Config from %s: %+v\n", filename, aux.Config)
	c.merge(&aux.Config)

	// BEGIN COMPATIBILITY WITH PYTHON CLI
	// The Python CLI uses the keys conjur_url and conjur_account
	// instead of appliance_url and account. Check if those keys
	// are present and use them if the new keys are not present.
	if c.ApplianceURL == "" && aux.ConjurURL != "" {
		c.ApplianceURL = aux.ConjurURL
	}

	if c.Account == "" && aux.ConjurAccount != "" {
		c.Account = aux.ConjurAccount
	}
	// END COMPATIBILITY WITH PYTHON CLI

	return nil
}

func (c *Config) mergeEnv() {
	env := Config{
		ApplianceURL:      os.Getenv("CONJUR_APPLIANCE_URL"),
		SSLCert:           os.Getenv("CONJUR_SSL_CERTIFICATE"),
		SSLCertPath:       os.Getenv("CONJUR_CERT_FILE"),
		Account:           os.Getenv("CONJUR_ACCOUNT"),
		NetRCPath:         os.Getenv("CONJUR_NETRC_PATH"),
		CredentialStorage: os.Getenv("CONJUR_CREDENTIAL_STORAGE"),
		AuthnType:         os.Getenv("CONJUR_AUTHN_TYPE"),
		ServiceID:         os.Getenv("CONJUR_SERVICE_ID"),
		JWTContent:        os.Getenv("CONJUR_AUTHN_JWT_TOKEN"),
		JWTFilePath:       os.Getenv("JWT_TOKEN_PATH"),
		JWTHostID:         os.Getenv("CONJUR_AUTHN_JWT_HOST_ID"),
		HTTPTimeout:       httpTimoutFromEnv(),
	}

	if os.Getenv("CONJUR_AUTHN_JWT_SERVICE_ID") != "" {
		// If the CONJUR_AUTHN_JWT_SERVICE_ID env var is set, we are implicitly using authn-jwt
		env.AuthnType = "jwt"
		// If using authn-jwt, CONJUR_AUTHN_JWT_SERVICE_ID overrides CONJUR_SERVICE_ID
		env.ServiceID = mergeValue(env.ServiceID, os.Getenv("CONJUR_AUTHN_JWT_SERVICE_ID"))
	}

	logging.ApiLog.Debugf("Config from environment: %+v\n", env)
	c.merge(&env)
}

func httpTimoutFromEnv() int {
	timeoutStr, ok := os.LookupEnv("CONJUR_HTTP_TIMEOUT")
	if !ok || len(timeoutStr) == 0 {
		return 0
	}
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil {
		logging.ApiLog.Infof(
			"Could not parse CONJUR_HTTP_TIMEOUT, using default value (%ds): %s",
			HTTPTimeoutDefaultValue,
			err)
		timeout = HTTPTimeoutDefaultValue
	}
	return timeout
}

func (c *Config) applyDefaults() {
	if isConjurCloudURL(c.ApplianceURL) && c.Account == "" {
		logging.ApiLog.Info("Detected Conjur Cloud URL, setting 'Account' to 'conjur")
		c.Account = "conjur"
	}
}

func (c *Config) Conjurrc() []byte {
	data, _ := yaml.Marshal(&c)
	return data
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

	config.applyDefaults()

	logging.ApiLog.Debugf("Final config: %+v\n", config)
	return config, nil
}

func getSystemPath() string {
	if runtime.GOOS == "windows" {
		// No way to use SHGetKnownFolderPath()
		// Hardcoding should be fine for now since CONJURRC is available
		return "C:\\windows"
	} else {
		return "/etc"
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// SetIntegrationName sets the name of the integration. If the provided name is
// an empty string, it defaults to "SecretsManagerGo SDK".
//
// Parameters:
//   - inname (string): The name of the integration. If empty, the default value is used.
func (c *Config) SetIntegrationName(inname string) {
	if inname == "" {
		c.IntegrationName = "SecretsManagerGo SDK"
	} else {
		c.IntegrationName = inname
	}
	c.finalTelemetryHeader = ""
}

// SetIntegrationType sets the type of the integration. If the provided type is
// an empty string, it defaults to "cybr-secretsmanager".
//
// Parameters:
//   - intype (string): The type of the integration. If empty, the default value is used.
func (c *Config) SetIntegrationType(intype string) {
	if intype == "" {
		c.IntegrationType = "cybr-secretsmanager"
	} else {
		c.IntegrationType = intype
	}
	c.finalTelemetryHeader = ""
}

// SetIntegrationVersion sets the version of the integration. If the provided version is
// an empty string, it tries to fetch the version from the "VERSION" file located in the parent
// directory of the current working directory.
//
// Parameters:
//   - inversion (string): The version of the integration. If empty, the version is fetched from the VERSION file.
func (c *Config) SetIntegrationVersion(inversion string) {
	if inversion == "" {
		currentDir, err := filepath.Abs(".")
		if err != nil {
			fmt.Errorf("Error getting current directory: %v", err)
		}
		vserionPath := filepath.Join(currentDir, "..", "VERSION")

		latestVersion, err := GetReleaseVersion(vserionPath)
		if err != nil {
			fmt.Errorf("Error: %v", err)
		}
		c.IntegrationVersion = latestVersion
	} else {
		c.IntegrationVersion = inversion
	}
	c.finalTelemetryHeader = ""
}

// SetVendorName sets the name of the vendor. If the provided name is an empty string, 
// it defaults to "CyberArk".
//
// Parameters:
//   - vname (string): The name of the vendor. If empty, the default value is used.
func (c *Config) SetVendorName(vname string) {
	if vname == "" {
		c.VendorName = "CyberArk"
	} else {
		c.VendorName = vname
	}
	c.finalTelemetryHeader = ""
}

// SetVendorVersion sets the version of the vendor. If the provided version is an empty string,
// it sets the vendor version to an empty string.
//
// Parameters:
//   - vversion (string): The version of the vendor. If empty, the vendor version is set to an empty string.
func (c *Config) SetVendorVersion(vversion string) {
	if vversion == "" {
		c.VendorVersion = ""
	} else {
		c.VendorVersion = vversion
	}
	c.finalTelemetryHeader = ""
}

// GetReleaseVersion reads the version from a specified file located at versionPath.
// It returns the version as a string or an error if the file cannot be read.
//
// Parameters:
//   - versionPath (string): The path to the VERSION file that contains the release version.
//
// Returns:
//   - string: The version read from the file.
//   - error: Any error that occurred while reading the file.
func GetReleaseVersion(versionPath string) (string, error) {
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "", fmt.Errorf("error reading VERSION file: %v", err)
	}
	return string(data), nil
}

// SetFinalTelemetryHeader constructs and returns a base64-encoded telemetry header
// based on the values of the integration and vendor properties. If the header has already been constructed, it returns the cached value.
//
// Returns:
//   - string: The base64-encoded telemetry header.
func (c *Config) SetFinalTelemetryHeader() string {
	if c.finalTelemetryHeader != "" {
		return c.finalTelemetryHeader
	}
	finalTelemetryHeader := ""
	if c.IntegrationName != "" {
		finalTelemetryHeader += "in=" + c.IntegrationName
		if c.IntegrationVersion != "" {
			finalTelemetryHeader += "&iv=" + c.IntegrationVersion
		}
		if c.IntegrationType != "" {
			finalTelemetryHeader += "&it=" + c.IntegrationType
		}
	}
	if c.VendorName != "" {
		finalTelemetryHeader += "&vn=" + c.VendorName
		if c.VendorVersion != "" {
			finalTelemetryHeader += "&vv=" + c.VendorVersion
		}
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(finalTelemetryHeader))
	c.finalTelemetryHeader = encodedHeader
	return c.finalTelemetryHeader
}
