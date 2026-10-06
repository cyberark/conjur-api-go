package contract

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func knownVersion(version string) func() (string, error) {
	return func() (string, error) { return version, nil }
}

var errVersionUnavailable = errors.New("failed to retrieve server version")

func unknownVersion() (string, error) {
	return "", errVersionUnavailable
}

// versionNotNeeded fails t if the backend version is requested, for cases
// where the answer must not depend on it.
func versionNotNeeded(t *testing.T) func() (string, error) {
	return func() (string, error) {
		t.Error("backend version should not be requested")
		return "", errors.New("unexpected version request")
	}
}

func requireNotSupported(t *testing.T, err error) *FeatureNotSupportedError {
	t.Helper()
	var target *FeatureNotSupportedError
	require.True(t, errors.As(err, &target), "expected *FeatureNotSupportedError, got %v", err)
	return target
}

func TestCheckCapability(t *testing.T) {
	t.Run("self-hosted, version too old -> FeatureNotSupportedError", func(t *testing.T) {
		target := requireNotSupported(t, CheckCapability(CapabilityBranchesV2, false, knownVersion("1.28.0")))
		assert.Equal(t, "Branch API", target.FeatureName)
		assert.Equal(t, "1.29.0", target.MinVersion)
		assert.Equal(t, "Branch API is not supported in Idira Secrets Manager versions older than 1.29.0", target.Error())
		assert.NoError(t, target.Err, "the version was known, so there is no lookup failure to report")
	})

	t.Run("self-hosted, version new enough -> nil", func(t *testing.T) {
		assert.NoError(t, CheckCapability(CapabilityBranchesV2, false, knownVersion("1.29.0")))
		assert.NoError(t, CheckCapability(CapabilityBranchesV2, false, knownVersion("1.29.0-11")))
	})

	t.Run("self-hosted, version unavailable -> blocked, with the lookup failure", func(t *testing.T) {
		err := CheckCapability(CapabilityBranchesV2, false, unknownVersion)
		target := requireNotSupported(t, err)
		assert.Equal(t, "1.29.0", target.MinVersion)
		assert.ErrorIs(t, err, errVersionUnavailable)
		assert.EqualError(t, err, "Branch API is not supported in Idira Secrets Manager versions older than 1.29.0 (server version unavailable: failed to retrieve server version)")
	})

	t.Run("self-hosted, unparseable version -> blocked", func(t *testing.T) {
		requireNotSupported(t, CheckCapability(CapabilityBranchesV2, false, knownVersion("0.0.dev")))
	})

	t.Run("SaaS-always-supported capability skips the version check on SaaS", func(t *testing.T) {
		assert.NoError(t, CheckCapability(CapabilityBranchesV2, true, versionNotNeeded(t)))
	})

	t.Run("SaaS-unsupported capability blocks on SaaS regardless of version", func(t *testing.T) {
		target := requireNotSupported(t, CheckCapability(CapabilityPolicyDryRun, true, versionNotNeeded(t)))
		assert.Equal(t, "Policy Dry Run is not supported in Idira Secrets Manager, SaaS", target.Error())
	})

	t.Run("LDAP mappings are blocked on SaaS", func(t *testing.T) {
		target := requireNotSupported(t, CheckCapability(CapabilityLdapMappings, true, versionNotNeeded(t)))
		assert.Equal(t, "LDAP JIT mappings is not supported in Idira Secrets Manager, SaaS", target.Error())
	})

	t.Run("SaaS-unsupported capability is fine on self-hosted once version is new enough", func(t *testing.T) {
		assert.NoError(t, CheckCapability(CapabilityPolicyDryRun, false, knownVersion("1.21.1")))
		target := requireNotSupported(t, CheckCapability(CapabilityPolicyDryRun, false, knownVersion("1.21.0")))
		assert.Equal(t, "Policy Dry Run is not supported in Idira Secrets Manager versions older than 1.21.1", target.Error())
	})

	t.Run("capability removed from self-hosted is blocked from the removal version on", func(t *testing.T) {
		assert.NoError(t, CheckCapability(CapabilityPublicKeys, false, knownVersion("1.26.9")))
		target := requireNotSupported(t, CheckCapability(CapabilityPublicKeys, false, knownVersion("1.27.0")))
		assert.Equal(t, "1.27.0", target.RemovedInVersion)
		assert.Equal(t, "Public Keys is not supported in Idira Secrets Manager versions 1.27.0 and later", target.Error())

		target = requireNotSupported(t, CheckCapability(CapabilityPublicKeys, true, versionNotNeeded(t)))
		assert.Equal(t, "Public Keys is not supported in Idira Secrets Manager, SaaS", target.Error())
	})

	t.Run("capability every version had until its removal names no minimum version", func(t *testing.T) {
		err := CheckCapability(CapabilityPublicKeys, false, unknownVersion)
		target := requireNotSupported(t, err)
		assert.Empty(t, target.MinVersion)
		assert.ErrorIs(t, err, errVersionUnavailable)
		assert.EqualError(t, err, "Public Keys is not supported by this Conjur server (server version unavailable: failed to retrieve server version)")
	})

	t.Run("SaaS-only capability blocks on self-hosted without needing the version", func(t *testing.T) {
		for _, cap := range []Capability{
			CapabilitySWAManagement,
			CapabilityWorkloadV2,
			CapabilityIssuerV2,
			CapabilityStaticSecretV2,
			CapabilityBatchRetrieveSecretsV2,
		} {
			target := requireNotSupported(t, CheckCapability(cap, false, versionNotNeeded(t)))
			assert.Equal(t, selfHostedPlatformLabel, target.Platform)
			assert.NoError(t, CheckCapability(cap, true, versionNotNeeded(t)))
		}
	})

	t.Run("SaaS-only error keeps the SDK's existing wording", func(t *testing.T) {
		err := CheckCapability(CapabilityWorkloadV2, false, versionNotNeeded(t))
		assert.EqualError(t, err, "Workload API is not supported in Idira Secrets Manager/Conjur OSS")
	})

	t.Run("unknown capability is never gated", func(t *testing.T) {
		assert.NoError(t, CheckCapability(Capability("does-not-exist"), false, versionNotNeeded(t)))
	})

	t.Run("a removed capability is blocked from the removal version on", func(t *testing.T) {
		cap := withTestCapability(t, "Widget API", capabilityEntry{
			SaaSPolicy: SaaSAlwaysSupported,
			Ranges: []capabilityRange{
				{fromVersion: "1.10.0"},
				{fromVersion: "2.0.0", removed: true},
			},
		})

		assert.NoError(t, CheckCapability(cap, false, knownVersion("1.99.0")))
		target := requireNotSupported(t, CheckCapability(cap, false, knownVersion("2.0.0")))
		assert.Equal(t, "2.0.0", target.RemovedInVersion)
		assert.Equal(t, "Widget API is not supported in Idira Secrets Manager versions 2.0.0 and later", target.Error())
	})
}

func TestCapabilityTable(t *testing.T) {
	for cap, entry := range capabilityTable {
		assert.NotEmpty(t, string(cap), "capability has no feature name")
		if entry.SaaSPolicy == SaaSOnly {
			assert.Empty(t, entry.Ranges, "%s is SaaS-only, so it has no self-hosted version range", cap)
		}
		for i, r := range entry.Ranges {
			assert.True(t, versionAtLeast(r.fromVersion, "0.0.0"), "%s has an unparseable version %q", cap, r.fromVersion)
			if i == 0 {
				assert.False(t, r.removed, "%s's first range must introduce the capability", cap)
			} else {
				assert.True(t, versionAtLeast(r.fromVersion, entry.Ranges[i-1].fromVersion), "%s's ranges are not ascending", cap)
			}
		}
	}
}

func TestCapabilityEntry_unsupportedError_MultiRangeLifecycle(t *testing.T) {
	// A capability introduced at 1.10.0 and removed again at 2.0.0.
	const cap = Capability("Widget API")
	entry := capabilityEntry{
		SaaSPolicy: SaaSAlwaysSupported,
		Ranges: []capabilityRange{
			{fromVersion: "1.10.0"},
			{fromVersion: "2.0.0", removed: true},
		},
	}

	t.Run("before introduction", func(t *testing.T) {
		err := entry.unsupportedError(cap, "1.9.0")
		require.NotNil(t, err)
		assert.Equal(t, "1.10.0", err.MinVersion)
		assert.Empty(t, err.RemovedInVersion)
	})

	t.Run("within the supported window", func(t *testing.T) {
		assert.Nil(t, entry.unsupportedError(cap, "1.10.0"))
		assert.Nil(t, entry.unsupportedError(cap, "1.99.0"))
	})

	t.Run("at and after removal", func(t *testing.T) {
		err := entry.unsupportedError(cap, "2.0.0")
		require.NotNil(t, err)
		assert.Equal(t, "2.0.0", err.RemovedInVersion)
		assert.Empty(t, err.MinVersion)

		err = entry.unsupportedError(cap, "3.0.0")
		require.NotNil(t, err)
		assert.Equal(t, "2.0.0", err.RemovedInVersion)
	})
}

func TestStatus(t *testing.T) {
	t.Run("version unavailable -> StatusUnknown", func(t *testing.T) {
		assert.Equal(t, StatusUnknown, Status(CapabilityBranchesV2, false, unknownVersion))
	})

	t.Run("known old version -> StatusUnsupported", func(t *testing.T) {
		assert.Equal(t, StatusUnsupported, Status(CapabilityBranchesV2, false, knownVersion("1.0.0")))
	})

	t.Run("known new-enough version -> StatusSupported", func(t *testing.T) {
		assert.Equal(t, StatusSupported, Status(CapabilityBranchesV2, false, knownVersion("1.29.0")))
	})

	t.Run("SaaS honors SaaSUnsupported without needing the version", func(t *testing.T) {
		assert.Equal(t, StatusUnsupported, Status(CapabilityPolicyFetch, true, versionNotNeeded(t)))
	})

	t.Run("SaaS honors SaaSAlwaysSupported without needing the version", func(t *testing.T) {
		assert.Equal(t, StatusSupported, Status(CapabilityBranchesV2, true, versionNotNeeded(t)))
	})

	t.Run("SaaS-only capability reports Unsupported on self-hosted and Supported on SaaS", func(t *testing.T) {
		assert.Equal(t, StatusUnsupported, Status(CapabilityWorkloadV2, false, versionNotNeeded(t)))
		assert.Equal(t, StatusSupported, Status(CapabilityWorkloadV2, true, versionNotNeeded(t)))
	})

	t.Run("unknown capability -> StatusSupported", func(t *testing.T) {
		assert.Equal(t, StatusSupported, Status(Capability("does-not-exist"), false, versionNotNeeded(t)))
	})
}

// withTestCapability registers entry under cap for the duration of t, so
// CheckCapability/Status can be exercised against shapes no shipped
// capability uses yet (e.g. a removal range).
func withTestCapability(t *testing.T, cap Capability, entry capabilityEntry) Capability {
	capabilityTable[cap] = entry
	t.Cleanup(func() { delete(capabilityTable, cap) })
	return cap
}

func TestVersionAtLeast(t *testing.T) {
	assert.True(t, versionAtLeast("1.23.0", "1.23.0"))
	assert.True(t, versionAtLeast("1.23.1", "1.23.0"))
	assert.True(t, versionAtLeast("1.21.1-359", "1.21.1"))
	assert.False(t, versionAtLeast("1.22.0", "1.23.0"))
	assert.False(t, versionAtLeast("", "1.23.0"))
	assert.False(t, versionAtLeast("not-a-version", "1.23.0"))
}
