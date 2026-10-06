// Package contract holds the SDK's compatibility matrix: which features the
// connected backend supports, based on its platform (SaaS vs. self-hosted)
// and, on self-hosted, its version.
package contract

import (
	semver "github.com/Masterminds/semver/v3"
)

// Platform names, worded as in the SDK's other error messages.
const (
	saaSPlatformLabel       = "Idira Secrets Manager, SaaS"
	selfHostedPlatformLabel = "Idira Secrets Manager/Conjur OSS"
)

// Capability names an SDK feature whose availability depends on the
// backend's platform or version. Its value is the human-readable name used
// in FeatureNotSupportedError messages - there's no separate internal slug,
// since nothing compares or serializes this value except by identity.
type Capability string

const (
	CapabilityAuthenticatorsV2       Capability = "Authenticators API"
	CapabilityLdapMappings           Capability = "LDAP JIT mappings"
	CapabilityBranchesV2             Capability = "Branch API"
	CapabilityGroupsV2               Capability = "Group API"
	CapabilityPolicyDryRun           Capability = "Policy Dry Run"
	CapabilityPolicyFetch            Capability = "Policy Fetch"
	CapabilityPublicKeys             Capability = "Public Keys"
	CapabilitySWAManagement          Capability = "SWA API"
	CapabilityWorkloadV2             Capability = "Workload API"
	CapabilityIssuerV2               Capability = "Issuer API"
	CapabilityStaticSecretV2         Capability = "StaticSecret API"
	CapabilityBatchRetrieveSecretsV2 Capability = "V2 Batch Retrieve Secrets API"
)

// SaaSPolicy is a capability's availability on SaaS.
type SaaSPolicy int

const (
	SaaSAlwaysSupported SaaSPolicy = iota // always available on SaaS
	SaaSUnsupported                       // never available on SaaS
	SaaSOnly                              // never available on self-hosted; Ranges is unused
)

// sinceFirstRelease is the fromVersion of a capability every version has had.
const sinceFirstRelease = "0.0.0"

// V2MinVersion is the first self-hosted version supporting the V2 APIs.
const V2MinVersion = "1.29.0"

// capabilityRange sets a capability's availability from fromVersion until
// the next range. A range adds the capability by default (removed is false,
// its zero value) - only a later removal range needs removed: true.
type capabilityRange struct {
	fromVersion string
	removed     bool
}

// capabilityEntry is one registry row. Ranges is ascending by fromVersion.
type capabilityEntry struct {
	SaaSPolicy SaaSPolicy
	Ranges     []capabilityRange
}

// capabilityTable holds every platform and version requirement the SDK
// enforces. Each entry also needs its routes in capability_routes.go.
var capabilityTable = map[Capability]capabilityEntry{
	CapabilityAuthenticatorsV2: {
		SaaSPolicy: SaaSAlwaysSupported,
		Ranges:     []capabilityRange{{fromVersion: V2MinVersion}},
	},
	CapabilityLdapMappings: {
		SaaSPolicy: SaaSUnsupported,
		Ranges:     []capabilityRange{{fromVersion: "1.28.0"}},
	},
	CapabilityBranchesV2: {
		SaaSPolicy: SaaSAlwaysSupported,
		Ranges:     []capabilityRange{{fromVersion: V2MinVersion}},
	},
	CapabilityGroupsV2: {
		SaaSPolicy: SaaSAlwaysSupported,
		Ranges:     []capabilityRange{{fromVersion: V2MinVersion}},
	},
	CapabilityPolicyDryRun: {
		SaaSPolicy: SaaSUnsupported,
		Ranges:     []capabilityRange{{fromVersion: "1.21.1"}},
	},
	CapabilityPolicyFetch: {
		SaaSPolicy: SaaSUnsupported,
		Ranges:     []capabilityRange{{fromVersion: "1.21.1"}},
	},
	CapabilityPublicKeys: {
		SaaSPolicy: SaaSUnsupported,
		Ranges: []capabilityRange{
			{fromVersion: sinceFirstRelease},
			{fromVersion: "1.27.0", removed: true},
		},
	},
	// SaaS-only APIs, with no self-hosted version to gate on.
	CapabilitySWAManagement:          {SaaSPolicy: SaaSOnly},
	CapabilityWorkloadV2:             {SaaSPolicy: SaaSOnly},
	CapabilityIssuerV2:               {SaaSPolicy: SaaSOnly},
	CapabilityStaticSecretV2:         {SaaSPolicy: SaaSOnly},
	CapabilityBatchRetrieveSecretsV2: {SaaSPolicy: SaaSOnly},
}

// platformError refuses cap on the platform, whatever the version.
func (e capabilityEntry) platformError(cap Capability, isSaaS bool) *FeatureNotSupportedError {
	if e.SaaSPolicy == SaaSUnsupported && isSaaS {
		return &FeatureNotSupportedError{FeatureName: string(cap), Platform: saaSPlatformLabel}
	}
	if e.SaaSPolicy == SaaSOnly && !isSaaS {
		return &FeatureNotSupportedError{FeatureName: string(cap), Platform: selfHostedPlatformLabel}
	}
	return nil
}

// minVersion is the version that added the capability, or "" if every version has it.
func (e capabilityEntry) minVersion() string {
	if e.Ranges[0].fromVersion == sinceFirstRelease {
		return ""
	}
	return e.Ranges[0].fromVersion
}

// needsVersion reports whether availability depends on the self-hosted version.
func (e capabilityEntry) needsVersion(isSaaS bool) bool {
	return !isSaaS && len(e.Ranges) > 0
}

// unsupportedError applies the highest range backendVersion has reached: none
// means the version is too old, an unsupported one that the capability was removed.
func (e capabilityEntry) unsupportedError(cap Capability, backendVersion string) *FeatureNotSupportedError {
	if len(e.Ranges) == 0 {
		return nil
	}

	var selected *capabilityRange
	for i := range e.Ranges {
		if versionAtLeast(backendVersion, e.Ranges[i].fromVersion) {
			selected = &e.Ranges[i]
		}
	}

	if selected == nil {
		return &FeatureNotSupportedError{FeatureName: string(cap), MinVersion: e.minVersion()}
	}
	if selected.removed {
		return &FeatureNotSupportedError{FeatureName: string(cap), RemovedInVersion: selected.fromVersion}
	}
	return nil
}

// versionAtLeast reports whether actualVersion >= minVersion, ignoring build
// suffixes (1.21.1-359). An unparseable version never meets it.
func versionAtLeast(actualVersion, minVersion string) bool {
	actual, err := semver.NewVersion(actualVersion)
	if err != nil {
		return false
	}
	min, err := semver.NewVersion(minVersion)
	if err != nil {
		return false
	}
	simplified, _ := actual.SetPrerelease("")
	return !simplified.LessThan(min)
}

// CheckCapability returns a *FeatureNotSupportedError if cap isn't available.
// backendVersion is called only when needed; if it fails, cap is refused and
// the error carries the failure in Err.
func CheckCapability(cap Capability, isSaaS bool, backendVersion func() (string, error)) error {
	entry, ok := capabilityTable[cap]
	if !ok {
		return nil
	}

	if err := entry.platformError(cap, isSaaS); err != nil {
		return err
	}
	if !entry.needsVersion(isSaaS) {
		return nil
	}

	version, err := backendVersion()
	if err != nil {
		return &FeatureNotSupportedError{FeatureName: string(cap), MinVersion: entry.minVersion(), Err: err}
	}
	if err := entry.unsupportedError(cap, version); err != nil {
		return err
	}
	return nil
}

// CapabilityStatus is a capability's availability, checked without making the call.
type CapabilityStatus int

const (
	StatusUnknown CapabilityStatus = iota // the version it depends on couldn't be retrieved
	StatusSupported
	StatusUnsupported
)

// Status reports cap's availability; StatusUnknown if a needed version lookup fails.
func Status(cap Capability, isSaaS bool, backendVersion func() (string, error)) CapabilityStatus {
	entry, ok := capabilityTable[cap]
	if !ok {
		return StatusSupported
	}

	if entry.platformError(cap, isSaaS) != nil {
		return StatusUnsupported
	}
	if !entry.needsVersion(isSaaS) {
		return StatusSupported
	}

	version, err := backendVersion()
	if err != nil {
		return StatusUnknown
	}
	if entry.unsupportedError(cap, version) != nil {
		return StatusUnsupported
	}
	return StatusSupported
}
