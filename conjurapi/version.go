package conjurapi

import (
	"fmt"

	semver "github.com/Masterminds/semver/v3"
)

// VerifyMinServerVersion checks if the server version is at least a certain version, using semantic versioning.
func (c *Client) VerifyMinServerVersion(minVersion string) error {
	serverVersion, err := c.ServerVersion()
	if err != nil {
		return err
	}

	return validateMinVersion(serverVersion, minVersion)
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

	if conjurVersion.LessThan(minConjurVersion) {
		return fmt.Errorf("Conjur version %s is less than the minimum required version %s", conjurVersion, minConjurVersion)
	}

	return nil
}
