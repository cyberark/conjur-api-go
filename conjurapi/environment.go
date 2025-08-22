package conjurapi

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type EnvironmentType string

const (
	EnvironmentSaaS EnvironmentType = "saas"
	EnvironmentSH   EnvironmentType = "self-hosted"
	EnvironmentOSS  EnvironmentType = "oss"
)

var SupportedEnvironments = []string{string(EnvironmentSaaS), string(EnvironmentSH), string(EnvironmentOSS)}

func (e *EnvironmentType) String() string {
	return string(*e)
}

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
	} else {
		if showLog {
			logging.ApiLog.Info("'Environment' not specified, setting to 'self-hosted'")
		}
		return EnvironmentSH
	}
}
