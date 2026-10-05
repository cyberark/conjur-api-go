package contract

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouteCapability(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		route  string
		want   Capability // "" means ungated
	}{
		// V2 APIs gated by version.
		{"authenticators list", http.MethodGet, "/authenticators/conjur", CapabilityAuthenticatorsV2},
		{"authenticator update", http.MethodPatch, "/authenticators/conjur/authn-jwt/svc", CapabilityAuthenticatorsV2},
		{"branch create", http.MethodPost, "/branches/conjur", CapabilityBranchesV2},
		{"branch read, SaaS (no account)", http.MethodGet, "/branches/data/apps", CapabilityBranchesV2},
		{"group read", http.MethodGet, "/groups/conjur/data/team", CapabilityGroupsV2},
		{"group delete", http.MethodDelete, "/groups/conjur/data/team", CapabilityGroupsV2},
		{"group annotation delete", http.MethodDelete, "/groups/conjur/data/team/annotations/owner", CapabilityGroupsV2},
		{"group members list", http.MethodGet, "/groups/conjur/data/team/members", CapabilityGroupsV2},
		{"group member add", http.MethodPost, "/groups/conjur/data/team/members", CapabilityGroupsV2},
		{"group member remove", http.MethodDelete, "/groups/conjur/data/team/members/host/data/app", CapabilityGroupsV2},
		{"ldap group mappings", http.MethodGet, "/authn-ldap/svc/conjur/groups", CapabilityLdapMappings},
		{"ldap user mapping create", http.MethodPost, "/authn-ldap/svc/conjur/users/alice", CapabilityLdapMappings},

		// SaaS-restricted APIs.
		{"public keys", http.MethodGet, "/public_keys/conjur/user/alice", CapabilityPublicKeys},
		{"policy fetch", http.MethodGet, "/policies/conjur/policy/root", CapabilityPolicyFetch},
		{"workload create", http.MethodPost, "/workloads", CapabilityWorkloadV2},
		{"workload read", http.MethodGet, "/workloads/data%2Fapp", CapabilityWorkloadV2},
		{"certificate issue", http.MethodPost, "/issuers/my-issuer/issue", CapabilityIssuerV2},
		{"certificate sign", http.MethodPost, "/issuers/my-issuer/sign", CapabilityIssuerV2},
		{"static secret create", http.MethodPost, "/secrets/static", CapabilityStaticSecretV2},
		{"static secret permissions", http.MethodGet, "/secrets/static/data/db/permissions", CapabilityStaticSecretV2},
		{"static secret delete", http.MethodDelete, "/secrets/static/data%2Fdb", CapabilityStaticSecretV2},
		{"batch secrets, SaaS", http.MethodPost, "/secrets/values", CapabilityBatchRetrieveSecretsV2},
		{"batch secrets, self-hosted", http.MethodPost, "/secrets/conjur/values", CapabilityBatchRetrieveSecretsV2},

		// Ungated routes, including ones whose identifiers contain a gated
		// route's name.
		{"v1 authenticators listing", http.MethodGet, "/authenticators", ""},
		{"plain policy load", http.MethodPost, "/policies/conjur/policy/root", ""},
		{"v1 secret under data/workloads", http.MethodGet, "/secrets/conjur/variable/data%2Fworkloads%2Fdb", ""},
		{"v1 secret under data/branches", http.MethodGet, "/secrets/conjur/variable/data%2Fbranches%2Fx", ""},
		{"v1 secret named values", http.MethodPost, "/secrets/conjur/variable/values", ""},
		{"v1 batch secrets", http.MethodGet, "/secrets", ""},
		{"v1 resource under data/authenticators", http.MethodGet, "/resources/conjur/variable/data%2Fauthenticators%2Fk", ""},
		{"v1 role named branches", http.MethodGet, "/roles/conjur/group/branches", ""},
		{"v1 role named workloads", http.MethodGet, "/roles/conjur/group/workloads", ""},
		{"v1 issuer create", http.MethodPost, "/issuers/conjur", ""},
		{"v1 issuer read", http.MethodGet, "/issuers/conjur/issue", ""},
		{"ldap authenticator status", http.MethodGet, "/authn-ldap/svc/conjur/status", ""},
		{"ldap authenticator enable", http.MethodPatch, "/authn-ldap/svc/conjur", ""},
		{"whoami", http.MethodGet, "/whoami", ""},
		{"root", http.MethodGet, "", ""},
		{"invalid escape", http.MethodGet, "/branches/%zz", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RouteCapability(tc.method, tc.route, url.Values{})
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want != "", ok)
		})
	}

	t.Run("group identifier containing a gated route's name stays a group route", func(t *testing.T) {
		got, _ := RouteCapability(http.MethodGet, "/groups/conjur/data/workloads/team", url.Values{})
		assert.Equal(t, CapabilityGroupsV2, got)
	})

	t.Run("an unclean path is matched as its cleaned form", func(t *testing.T) {
		got, _ := RouteCapability(http.MethodGet, "/secrets/conjur/../../branches/conjur", url.Values{})
		assert.Equal(t, CapabilityBranchesV2, got)
		got, _ = RouteCapability(http.MethodGet, "//branches/conjur", url.Values{})
		assert.Equal(t, CapabilityBranchesV2, got)
	})

	t.Run("policy dry run only matches dryRun=true", func(t *testing.T) {
		got, ok := RouteCapability(http.MethodPost, "/policies/conjur/policy/root", url.Values{"dryRun": {"true"}})
		assert.True(t, ok)
		assert.Equal(t, CapabilityPolicyDryRun, got)

		_, ok = RouteCapability(http.MethodPost, "/policies/conjur/policy/root", url.Values{"dryRun": {"false"}})
		assert.False(t, ok)
	})

	t.Run("every capability has a route or an explicit caller", func(t *testing.T) {
		routed := map[Capability]bool{}
		for _, tc := range testCases {
			routed[tc.want] = true
		}
		routed[CapabilityPolicyDryRun] = true
		// SWA builds its own client rather than sending requests through
		// the SDK, so SWA() checks this capability itself.
		routed[CapabilitySWAManagement] = true

		for cap := range capabilityTable {
			assert.True(t, routed[cap], "%s is never matched by RouteCapability", cap)
		}
	})
}
