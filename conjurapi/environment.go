package conjurapi

import (
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"slices"
	"strings"
)

type EnvironmentType string

const (
	EnvironmentCC  EnvironmentType = "cloud"
	EnvironmentCE  EnvironmentType = "enterprise"
	EnvironmentOSS EnvironmentType = "oss"
)

var SupportedEnvironments = []string{string(EnvironmentCC), string(EnvironmentCE), string(EnvironmentOSS)}

func (e *EnvironmentType) String() string {
	return string(*e)
}

func (e *EnvironmentType) Set(value string) error {
	switch value {
	case string(EnvironmentCE), "CE":
		*e = EnvironmentCE
	case string(EnvironmentOSS), "OSS", "open-source":
		*e = EnvironmentOSS
	case string(EnvironmentCC), "CC":
		*e = EnvironmentCC
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
			logging.ApiLog.Info("Detected Conjur Cloud URL, setting 'Environment' to 'cloud'")
		}
		return EnvironmentCC
	} else {
		if showLog {
			logging.ApiLog.Info("'Environment' not specified, setting to 'enterprise'")
		}
		return EnvironmentCE
	}
}
