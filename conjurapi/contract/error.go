package contract

import "fmt"

// FeatureNotSupportedError is returned client-side when the backend doesn't
// offer a capability. At most one of MinVersion, RemovedInVersion or Platform
// is set. Err, returned by Unwrap, is set when the version couldn't be retrieved.
type FeatureNotSupportedError struct {
	FeatureName      string
	MinVersion       string
	RemovedInVersion string
	Platform         string
	Err              error
}

func (e *FeatureNotSupportedError) Error() string {
	if e.Platform != "" {
		return fmt.Sprintf("%s is not supported in %s", e.FeatureName, e.Platform)
	}
	if e.RemovedInVersion != "" {
		return fmt.Sprintf("%s is not supported in Idira Secrets Manager versions %s and later", e.FeatureName, e.RemovedInVersion)
	}
	if e.MinVersion != "" && e.Err != nil {
		return fmt.Sprintf("%s is not supported in Idira Secrets Manager versions older than %s (server version unavailable: %v)", e.FeatureName, e.MinVersion, e.Err)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s is not supported by this Conjur server (server version unavailable: %v)", e.FeatureName, e.Err)
	}
	if e.MinVersion != "" {
		return fmt.Sprintf("%s is not supported in Idira Secrets Manager versions older than %s", e.FeatureName, e.MinVersion)
	}
	return fmt.Sprintf("%s is not supported by this Conjur server", e.FeatureName)
}

func (e *FeatureNotSupportedError) Unwrap() error {
	return e.Err
}
