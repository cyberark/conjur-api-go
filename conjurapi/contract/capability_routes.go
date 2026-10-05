package contract

import (
	"net/http"
	"net/url"
)

// routeCapabilities maps gated routes, as http.ServeMux patterns relative to
// the API base URL, to their Capability. Unlisted routes aren't gated.
var routeCapabilities = map[string]Capability{
	// The v1 GET /authenticators listing isn't gated.
	"/authenticators/{account}":           CapabilityAuthenticatorsV2,
	"/authenticators/{account}/{rest...}": CapabilityAuthenticatorsV2,

	"/branches":  CapabilityBranchesV2,
	"/branches/": CapabilityBranchesV2,

	"/groups":  CapabilityGroupsV2,
	"/groups/": CapabilityGroupsV2,

	"/workloads":  CapabilityWorkloadV2,
	"/workloads/": CapabilityWorkloadV2,

	// The LDAP login, authenticate and status routes aren't gated.
	"/authn-ldap/{service_id}/{account}/groups":        CapabilityLdapMappings,
	"/authn-ldap/{service_id}/{account}/groups/{name}": CapabilityLdapMappings,
	"/authn-ldap/{service_id}/{account}/users":         CapabilityLdapMappings,
	"/authn-ldap/{service_id}/{account}/users/{name}":  CapabilityLdapMappings,

	"/public_keys/": CapabilityPublicKeys,

	// Dry run is the policy load route plus a query; see RouteCapability.
	"GET /policies/": CapabilityPolicyFetch,
	"/policies/":     CapabilityPolicyDryRun,

	// The issuers CRUD routes aren't gated.
	"POST /issuers/{name}/issue": CapabilityIssuerV2,
	"POST /issuers/{name}/sign":  CapabilityIssuerV2,

	// Per method: a POST under /secrets/static/ would conflict with the
	// self-hosted batch route, since /secrets/static/values matches both.
	"POST /secrets/static":           CapabilityStaticSecretV2,
	"GET /secrets/static/{id...}":    CapabilityStaticSecretV2,
	"PUT /secrets/static/{id...}":    CapabilityStaticSecretV2,
	"PATCH /secrets/static/{id...}":  CapabilityStaticSecretV2,
	"DELETE /secrets/static/{id...}": CapabilityStaticSecretV2,
	"POST /secrets/values":           CapabilityBatchRetrieveSecretsV2,
	"POST /secrets/{account}/values": CapabilityBatchRetrieveSecretsV2,
}

// routeMux only reports which pattern a request matches. Under
// GODEBUG=httpmuxgo121=1, method and wildcard patterns never match, so go ungated.
var routeMux = func() *http.ServeMux {
	mux := http.NewServeMux()
	for pattern := range routeCapabilities {
		mux.Handle(pattern, http.NotFoundHandler())
	}
	return mux
}()

// RouteCapability reports the Capability, if any, that governs a request.
// route is the still-escaped path relative to the API base URL, matched as
// http.ServeMux would, so "data%2Fworkloads%2Fdb" stays one segment.
func RouteCapability(method, route string, query url.Values) (Capability, bool) {
	path, err := url.PathUnescape(route)
	if err != nil {
		return "", false
	}
	_, pattern := routeMux.Handler(&http.Request{Method: method, URL: &url.URL{Path: path, RawPath: route}})
	cap, ok := routeCapabilities[pattern]
	if !ok {
		return "", false
	}

	if cap == CapabilityPolicyDryRun && query.Get("dryRun") != "true" {
		return "", false
	}
	return cap, true
}
