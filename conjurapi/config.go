package conjurapi

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"encoding/base64"
	"path/filepath"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

const (
	// HTTPTimeoutDefaultValue is the default value for the HTTP client timeout
	HTTPTimeoutDefaultValue = 60
	// HTTPTimeoutMaxValue is the maximum value allowed for the HTTP client timeout
	HTTPTimeoutMaxValue = 600
	// HTTPDialTimeout is the default value for the DialTimeout in the HTTP client
	HTTPDialTimeout = 10
	// DisableKeepAlivesDefaultValue is the default value for DisableKeepAlivesDefaultValue in the HTTP client
	DisableKeepAlivesDefaultValue = false

	ConjurSourceHeader = "x-cybr-telemetry"
)

var supportedAuthnTypes = []string{"authn", "ldap", "oidc", "jwt", "iam", "azure", "gcp", "cloud"}

type Config struct {
	Account              string          `yaml:"account,omitempty"`
	ApplianceURL         string          `yaml:"appliance_url,omitempty"`
	NetRCPath            string          `yaml:"netrc_path,omitempty"`
	SSLCert              string          `yaml:"-"`
	SSLCertPath          string          `yaml:"cert_file,omitempty"`
	AuthnType            string          `yaml:"authn_type,omitempty"`
	ServiceID            string          `yaml:"service_id,omitempty"`
	CredentialStorage    string          `yaml:"credential_storage,omitempty"`
	JWTHostID            string          `yaml:"jwt_host_id,omitempty"`
	JWTContent           string          `yaml:"-"`
	JWTFilePath          string          `yaml:"jwt_file,omitempty"`
	HTTPTimeout          int             `yaml:"http_timeout,omitempty"`
	DisableKeepAlives    bool            `yaml:"disable_keep_alives,omitempty"`
	IntegrationName      string          `yaml:"-"`
	IntegrationType      string          `yaml:"-"`
	IntegrationVersion   string          `yaml:"-"`
	VendorVersion        string          `yaml:"-"`
	VendorName           string          `yaml:"-"`
	finalTelemetryHeader string          `yaml:"-"`
	Environment          EnvironmentType `yaml:"environment,omitempty"`
	Proxy                string          `yaml:"proxy,omitempty"`
	ConjurCloudTimeout   int             `yaml:"cc_timeout,omitempty"`
	AzureClientID        string          `yaml:"azure_client_id,omitempty"`
}

func (c *Config) IsHttps() bool {
	return c.SSLCertPath != "" || c.SSLCert != ""
}

func (c *Config) Validate() error {
	c.applyDefaults(false)

	errors := []string{}

	if c.ApplianceURL == "" {
		errors = append(errors, "Must specify an ApplianceURL")
	}

	if c.Account == "" {
		errors = append(errors, "Must specify an Account")
	}

	if c.Environment == "" {
		errors = append(errors, "Must specify an Environment")
	}

	if c.AuthnType != "" && !contains(supportedAuthnTypes, c.AuthnType) {
		errors = append(errors, fmt.Sprintf("AuthnType must be one of %v", supportedAuthnTypes))
	}

	if (c.AuthnType == "ldap" || c.AuthnType == "oidc" || c.AuthnType == "jwt" || c.AuthnType == "iam" || c.AuthnType == "azure") && c.ServiceID == "" {
		errors = append(errors, fmt.Sprintf("Must specify a ServiceID when using %s", c.AuthnType))
	}

	if c.AuthnType == "jwt" && (c.JWTContent == "" && c.JWTFilePath == "") {
		errors = append(errors, fmt.Sprintf("Must specify a JWT token when using %s authentication", c.AuthnType))
	}

	if (c.AuthnType == "iam" || c.AuthnType == "azure") && c.JWTHostID == "" {
		errors = append(errors, fmt.Sprintf("Must specify a HostID when using %s authentication", c.AuthnType))
	}

	if c.HTTPTimeout < 0 || c.HTTPTimeout > HTTPTimeoutMaxValue {
		errors = append(errors, fmt.Sprintf("HTTPTimeout must be between 1 and %d seconds", HTTPTimeoutMaxValue))
	}

	if c.Environment != "" && !environmentIsSupported(string(c.Environment)) {
		errors = append(errors, fmt.Sprintf("Environment must be one of %v, got '%s'", SupportedEnvironments, strings.ToLower(string(c.Environment))))
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

func mergeValue[T comparable](a, b T) T {
	if b != *new(T) { // Check if `b` is not the zero value for its type
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
	c.HTTPTimeout = mergeValue(c.HTTPTimeout, o.HTTPTimeout)
	c.DisableKeepAlives = mergeValue(c.DisableKeepAlives, o.DisableKeepAlives)
	c.Environment = EnvironmentType(mergeValue(string(c.Environment), string(o.Environment)))
	c.Proxy = mergeValue(c.Proxy, o.Proxy)
	c.AzureClientID = mergeValue(c.AzureClientID, o.AzureClientID)
}

func (c *Config) mergeYAML(filename string) error {
	// Read the YAML file
	buf, err := os.ReadFile(filename)

	if err != nil {
		logging.ApiLog.Debugf("Failed reading %s, %v\n", filename, err)
		return err
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
		DisableKeepAlives: disableKeepAlivesFromEnv(),
		Environment:       EnvironmentType(os.Getenv("CONJUR_ENVIRONMENT")),
		Proxy:             os.Getenv("HTTPS_PROXY"),
		AzureClientID:     os.Getenv("CONJUR_AUTHN_AZURE_CLIENT_ID"),
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

func disableKeepAlivesFromEnv() bool {
	disableKeepAlivesStr, ok := os.LookupEnv("CONJUR_DISABLE_KEEP_ALIVES")
	if !ok || len(disableKeepAlivesStr) == 0 {
		return DisableKeepAlivesDefaultValue
	}

	value, err := strconv.ParseBool(disableKeepAlivesStr)
	if err != nil {
		logging.ApiLog.Infof(
			"Could not parse CONJUR_DISABLE_KEEP_ALIVES, using default value (%t): %s",
			DisableKeepAlivesDefaultValue,
			err)
	} else {
		return value
	}
	return DisableKeepAlivesDefaultValue
}

func (c *Config) applyDefaults(persist bool) {
	if isConjurCloudURL(c.ApplianceURL) && len(c.Account) == 0 {
		logging.ApiLog.Info("Detected Secrets Manager SaaS URL, setting 'Account' to 'conjur'")
		c.Account = "conjur"
		if persist {
			c.AddToConjurRc("account", c.Account)
		}
	}
	if len(c.Environment) == 0 {
		c.Environment = defaultEnvironment(c.ApplianceURL, persist)
		if persist {
			c.AddToConjurRc("environment", string(c.Environment))
		}
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

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return config, err
	}

	conjurrcExists := false
	conjurrc := os.Getenv("CONJURRC")
	if len(conjurrc) == 0 && len(home) > 0 {
		conjurrc = path.Join(home, ".conjurrc")
	}
	if len(conjurrc) > 0 {
		err = config.mergeYAML(conjurrc)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return config, err
		}
		if err == nil {
			conjurrcExists = true
		}
	}

	config.mergeEnv()

	config.applyDefaults(conjurrcExists)

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
	c.IntegrationName = inname
	c.finalTelemetryHeader = ""
}

// SetIntegrationType sets the type of the integration.
// Parameters:
//   - intype (string): The type of the integration.
func (c *Config) SetIntegrationType(intype string) {
	c.IntegrationType = intype
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

// SetVendorName sets the name of the vendor.
// Parameters:
//   - vname (string): The name of the vendor.
func (c *Config) SetVendorName(vname string) {
	c.VendorName = vname
	c.finalTelemetryHeader = ""
}

// SetVendorVersion sets the version of the vendor.
// Parameters:
//   - vversion (string): The version of the vendor.
func (c *Config) SetVendorVersion(vversion string) {
	c.VendorVersion = vversion
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

func (c *Config) setDefaultIntegrationMetadata() {
	if c.IntegrationName == "" {
		c.SetIntegrationName("SecretsManagerGo SDK")
	}
	if c.IntegrationType == "" {
		c.SetIntegrationType("cybr-secretsmanager")
	}
	if c.IntegrationVersion == "" {
		c.SetIntegrationVersion("")
	}
	if c.VendorName == "" {
		c.SetVendorName("CyberArk")
	}
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

	c.setDefaultIntegrationMetadata()

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

// IsSaaS returns true if the Environment is set to SaaS, false otherwise.
func (c *Config) IsSaaS() bool {
	return c.Environment == EnvironmentSaaS
}

// IsSelfHosted returns true if the Environment is set to Self-Hosted, false otherwise.
func (c *Config) IsSelfHosted() bool {
	return c.Environment == EnvironmentSH
}

// IsConjurOSS returns true if the Environment is set to Conjur OSS, false otherwise.
func (c *Config) IsConjurOSS() bool {
	return c.Environment == EnvironmentOSS
}

// ProxyURL parses the Proxy string from the Config and returns a url.URL pointer. If the Proxy string is empty or invalid, it returns nil.
func (c *Config) ProxyURL() *url.URL {
	if len(c.Proxy) == 0 {
		return nil
	}
	proxyURL, err := url.Parse(c.Proxy)
	if err != nil {
		logging.ApiLog.Errorf("Failed to parse proxy URL: %v", err)
		return nil
	}
	return proxyURL
}

// AddToConjurRc appends a key-value pair to the conjurrc file located at $CONJURRC or ~/.conjurrc if $CONJURRC is not set.
// If the home directory cannot be determined, it logs a warning and attempts to use $CONJURRC directly.
// Parameters:
//   - key (string): The key to add to the conjurrc file.
//   - val (string): The value associated with the key.
func (c *Config) AddToConjurRc(key, val string) {
	home, err := os.UserHomeDir()
	if err != nil {
		logging.ApiLog.Warningf("Could not detect homedir.")
	}

	conjurrc := os.Getenv("CONJURRC")
	if conjurrc == "" && home != "" {
		conjurrc = path.Join(home, ".conjurrc")
	}

	// append the key-value pair to the conjurrc file
	file, err := os.OpenFile(conjurrc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logging.ApiLog.Errorf("Failed to open %s: %v", conjurrc, err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("%s: %s\n", key, val)); err != nil {
		logging.ApiLog.Errorf("Failed to write to %s: %v", conjurrc, err)
		return
	}
}
