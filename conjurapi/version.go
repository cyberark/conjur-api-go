package conjurapi

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"sync"

	semver "github.com/Masterminds/semver/v3"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// VerifyMinServerVersion checks if the server version is at least a certain version, using semantic versioning.
func (c *Client) VerifyMinServerVersion(minVersion string) error {
	actualVersion, err := c.version.get(c.fetchAndPersistServerVersion)
	if err != nil {
		return err
	}
	return validateMinVersion(actualVersion, minVersion)
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

// serverVersion is a Client's in-memory cache of the backend's server
// version: fetched at most once, kept for the Client's whole life. A version
// change mid-life (a server upgrade) is the exception, not the common case,
// and is handled by explicitly dropping the cache (see forgetConfirmed), not
// by routinely re-checking it.
type serverVersion struct {
	mu    sync.RWMutex
	value string
}

// preload seeds the cache with version, as already known from an earlier
// run's .conjurrc. Must be called before the Client holding this cache is
// shared with any other goroutine (see NewClient).
func (v *serverVersion) preload(version string) {
	v.value = version
}

// get returns the server version, calling fetch to retrieve it if not
// already cached. A failed fetch isn't cached, so a transient failure can be
// retried on the next call.
func (v *serverVersion) get(fetch func() (string, error)) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.value == "" {
		version, err := fetch()
		if err != nil {
			return "", err
		}
		v.value = version
	}
	return v.value, nil
}

// known returns the cached server version, without retrieving it.
func (v *serverVersion) known() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.value
}

// forgetConfirmed drops a confirmed-stale version (e.g. a 426 Upgrade
// Required refusal), unless another caller already replaced it. If the
// refusal named a usable current version, that's cached directly, sparing a
// separate lookup; otherwise (including an unparseable hint) the cache is
// just cleared, and the next get() call fetches it as usual.
func (v *serverVersion) forgetConfirmed(stale, hinted string) {
	if _, err := semver.NewVersion(hinted); err != nil {
		hinted = ""
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.value != stale {
		return
	}
	v.value = hinted
}

// backendVersion is the version provider passed to contract.CheckCapability
// and contract.Status: the cached version, fetched (and persisted) if not
// already known.
func (c *Client) backendVersion() (string, error) {
	return c.version.get(c.fetchAndPersistServerVersion)
}

// fetchAndPersistServerVersion retrieves the server version and, on
// success, saves it to .conjurrc on a best-effort basis.
func (c *Client) fetchAndPersistServerVersion() (string, error) {
	version, err := c.ServerVersion()
	if err != nil {
		return "", err
	}
	c.version.persist(version)
	return version, nil
}

// pin sets req's Contract-Version to the cached version, if any, and
// returns it.
func (v *serverVersion) pin(req *http.Request) string {
	version := v.known()
	if version != "" {
		req.Header.Set(contractVersionHeader, version)
	}
	return version
}

// persist saves a usable version to .conjurrc, on a best-effort basis, if
// an existing .conjurrc is there to update - this never creates one, so a
// Client with no file (the common case for library consumers that build a
// Config programmatically) never gets a surprise file written to it. It
// rewrites the whole file from a Config read fresh from disk - not the
// Client's own c.config, which may hold values merged in from the
// environment that must not be baked into the file.
func (v *serverVersion) persist(version string) {
	if _, err := semver.NewVersion(version); err != nil {
		return
	}

	conjurrc, err := conjurrcPath()
	if err != nil {
		logging.ApiLog.Debugf("Not saving the server version: %v", err)
		return
	}
	if _, err := os.Stat(conjurrc); err != nil {
		return
	}

	// mergeYAML (not a bare yaml.Unmarshal) so a file using the legacy
	// Python-CLI keys (conjur_url/conjur_account) round-trips correctly
	// instead of silently losing ApplianceURL/Account on this rewrite.
	var fileConfig Config
	_ = fileConfig.mergeYAML(conjurrc) // best-effort; write version alone on a parse failure
	fileConfig.ServerVersion = version

	if err := os.WriteFile(conjurrc, fileConfig.Conjurrc(), 0600); err != nil {
		logging.ApiLog.Debugf("Not saving the server version: %v", err)
	}
}

// conjurrcPath resolves .conjurrc's path exactly as LoadConfig does: $CONJURRC
// if set, else ~/.conjurrc.
func conjurrcPath() (string, error) {
	if conjurrc := os.Getenv("CONJURRC"); conjurrc != "" {
		return conjurrc, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not detect homedir: %w", err)
	}
	return path.Join(home, ".conjurrc"), nil
}
