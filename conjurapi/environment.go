package conjurapi

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// EnvironmentType represents the type of Secrets Manager environment.
type EnvironmentType string

const (
	// EnvironmentSaaS represents the Secrets Manager SaaS environment.
	EnvironmentSaaS EnvironmentType = "saas"
	// EnvironmentSH represents the Secrets Manager Self-Hosted environment.
	EnvironmentSH EnvironmentType = "self-hosted"
	// EnvironmentOSS represents the Conjur Open Source environment.
	EnvironmentOSS EnvironmentType = "oss"
)

// SupportedEnvironments lists all supported environment types.
var SupportedEnvironments = []string{string(EnvironmentSaaS), string(EnvironmentSH), string(EnvironmentOSS)}

// String returns the string representation of the EnvironmentType.
func (e *EnvironmentType) String() string {
	return string(*e)
}

// FullName returns the full descriptive name of the EnvironmentType.
func (e *EnvironmentType) FullName() string {
	switch *e {
	case EnvironmentSaaS:
		return "Secrets Manager SaaS"
	case EnvironmentSH:
		return "Secrets Manager Self-Hosted"
	case EnvironmentOSS:
		return "Conjur Open Source"
	default:
		return "Unknown Environment"
	}
}

// Set sets the EnvironmentType based on the provided string value.
func (e *EnvironmentType) Set(value string) error {
	switch value {
	case string(EnvironmentSH), "CE", "enterprise":
		*e = EnvironmentSH
	case string(EnvironmentOSS), "OSS", "open-source":
		*e = EnvironmentOSS
	case string(EnvironmentSaaS), "cloud", "CC":
		*e = EnvironmentSaaS
	default:
		return fmt.Errorf("invalid value environment: %s, allowed values %v", value, SupportedEnvironments)
	}
	return nil
}

// Type returns the type of the EnvironmentType for flag parsing.
func (e *EnvironmentType) Type() string {
	return "string"
}

func environmentIsSupported(environment string) bool {
	return slices.Contains(SupportedEnvironments, strings.ToLower(environment))
}

func defaultEnvironment(url string, showLog bool) EnvironmentType {
	if isConjurCloudURL(url) {
		if showLog {
			logging.ApiLog.Info("Detected Secrets Manager SaaS URL, setting 'Environment' to 'saas'")
		}
		return EnvironmentSaaS
	}
	if showLog {
		logging.ApiLog.Info("'Environment' not specified, setting to 'self-hosted'")
	}
	return EnvironmentSH
}
