package conjurapi

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
)

const (
	IntegrationName    = "Secrets Manager Go"
	IntegrationType    = "cybr-secretsmanager"
	IntegrationVersion = "0.0.0"
	VendorName         = "CyberArk"
	VendorVersion      = ""
	conjurModulePath   = "github.com/cyberark/conjur-api-go"
)

var integrationVersionEnvVars = []string{
	"CONJUR_INTEGRATION_VERSION",
	"INTEGRATION_VERSION",
	"APP_VERSION",
}

type Telemetry struct {
	IntegrationName    string
	IntegrationType    string
	IntegrationVersion string
	VendorName         string
	VendorVersion      string
}

// NewTelemetry requires 5 args.
// Pass "" for any field you want to default from consts.
func NewTelemetry(
	integrationName string,
	integrationType string,
	integrationVersion string,
	vendorName string,
	vendorVersion string,
) Telemetry {
	return Telemetry{
		IntegrationName:    defaultIfNoOthers(integrationName, readIntegrationName, IntegrationName),
		IntegrationType:    defaultIfNoOthers(integrationType, readIntegrationType, IntegrationType),
		IntegrationVersion: defaultIfNoOthers(integrationVersion, readIntegrationVersion, IntegrationVersion),
		VendorName:         defaultIfNoOthers(vendorName, readVendorName, VendorName),
		VendorVersion:      defaultIfNoOthers(vendorVersion, readVendorVersion, VendorVersion),
	}
}

var (
	buildInfo     *debug.BuildInfo
	buildInfoOk   bool
	buildInfoOnce sync.Once
)

func defaultIfNoOthers(input string, readValue func() string, fallback string) string {
	if strings.TrimSpace(input) != "" {
		return input
	}

	if detected := strings.TrimSpace(readValue()); detected != "" {
		return detected
	}

	return fallback
}

// readBuildInfoValue reads the build info and applies the provided read function to it,
// returning an empty string if the build info is not available or if the read function returns an empty string.
// For removing duplication of code in readXyz functions
func readBuildInfoValue(read func(*debug.BuildInfo) string) string {
	binfo, ok := readBuildInfo()
	if !ok {
		return ""
	}
	return read(binfo)
}

func readIntegrationName() string {
	return readBuildInfoValue(func(binfo *debug.BuildInfo) string {
		modulePath := binfo.Main.Path
		if modulePath == "" {
			modulePath = binfo.Path
		}
		if modulePath == "" {
			return ""
		}
		return filepath.Base(filepath.Clean(modulePath))
	})
}

func readIntegrationType() string {
	return ""
}

func readIntegrationVersion() string {
	if version := readBuildInfoValue(readMainVersion); version != "" {
		return version
	}
	if version := readBuildInfoValue(readConjurDependencyVersion); version != "" {
		return version
	}
	if version := readIntegrationVersionFromEnv(); version != "" {
		return version
	}
	return readIntegrationVersionFromVersionFiles()
}

func readVendorName() string {
	return ""
}

func readVendorVersion() string {
	return ""
}

func readBuildInfo() (*debug.BuildInfo, bool) {
	buildInfoOnce.Do(func() {
		buildInfo, buildInfoOk = debug.ReadBuildInfo()
	})
	return buildInfo, buildInfoOk
}

func readMainVersion(binfo *debug.BuildInfo) string {
	return normalizeVersion(binfo.Main.Version)
}

func readConjurDependencyVersion(binfo *debug.BuildInfo) string {
	for _, dep := range binfo.Deps {
		if dep == nil || dep.Path != conjurModulePath {
			continue
		}
		if version := normalizeVersion(dep.Version); version != "" {
			return version
		}
		if dep.Replace != nil {
			if version := normalizeVersion(dep.Replace.Version); version != "" {
				return version
			}
		}
	}
	return ""
}

func readIntegrationVersionFromEnv() string {
	for _, envKey := range integrationVersionEnvVars {
		if version := normalizeVersion(os.Getenv(envKey)); version != "" {
			return version
		}
	}
	return ""
}

func readIntegrationVersionFromVersionFiles() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	for _, candidate := range []string{
		filepath.Join(cwd, "VERSION"),
		filepath.Join(cwd, "..", "VERSION"),
	} {
		if data, err := os.ReadFile(candidate); err == nil {
			if version := normalizeVersion(string(data)); version != "" {
				return version
			}
		}
	}

	return ""
}

func normalizeVersion(raw string) string {
	version := strings.TrimSpace(raw)
	if version == "" || version == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(version, "v")
}
