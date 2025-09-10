package conjurapi

import (
	"fmt"

	semver "github.com/Masterminds/semver/v3"
)

// VerifyMinServerVersion checks if the server version is at least a certain version, using semantic versioning.
func (c *Client) VerifyMinServerVersion(minVersion string) error {
	if c.conjurVersion == "" {
		serverVersion, err := c.ServerVersion()
		if err != nil {
			return err
		}

		c.conjurVersion = serverVersion
	}
	return validateMinVersion(c.conjurVersion, minVersion)
}

// Validates that the actual version is at least the minimum version, using semantic versioning.
func validateMinVersion(actualVersion string, minVersion string) error {
	conjurVersion, err := semver.NewVersion(actualVersion)
	if err != nil {
		return fmt.Errorf("failed to parse server version: %s", err)
	}

	minConjurVersion, err := semver.NewVersion(minVersion)
	if err != nil {
		return fmt.Errorf("failed to parse minimum version: %s", err)
	}

	// Ignore version suffixes (eg. 1.21.1-359) as we use them differently in the Conjur versioning scheme.
	// In SemVer, the suffix is considered a pre-release version, but in Conjur, it is used as a build version.
	simplifiedVersion, _ := conjurVersion.SetPrerelease("")

	if simplifiedVersion.LessThan(minConjurVersion) {
		return fmt.Errorf("Conjur version %s is less than the minimum required version %s", conjurVersion, minConjurVersion)
	}

	return nil
}
