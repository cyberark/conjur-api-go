package swaerrors

// Op constants enumerate every SDK operation. They are the only valid values
// for the Op field on *APIError and *ValidationError, giving callers and logs a
// stable, single source of truth.
//
// Usage:
//
//	if apiErr.Op == OpServersCreate { ... }
const (
	// Trust domains (main control-plane surface).
	OpTrustDomainsGet    Op = "TrustDomains.Get"
	OpTrustDomainsList   Op = "TrustDomains.List"
	OpTrustDomainsCreate Op = "TrustDomains.Create"
	OpTrustDomainsUpdate Op = "TrustDomains.Update"
	OpTrustDomainsDelete Op = "TrustDomains.Delete"

	// Server groups.
	OpServerGroupsGet    Op = "ServerGroups.Get"
	OpServerGroupsList   Op = "ServerGroups.List"
	OpServerGroupsCreate Op = "ServerGroups.Create"
	OpServerGroupsUpdate Op = "ServerGroups.Update"
	OpServerGroupsDelete Op = "ServerGroups.Delete"

	// Node groups.
	OpNodeGroupsGet    Op = "NodeGroups.Get"
	OpNodeGroupsList   Op = "NodeGroups.List"
	OpNodeGroupsCreate Op = "NodeGroups.Create"
	OpNodeGroupsUpdate Op = "NodeGroups.Update"
	OpNodeGroupsDelete Op = "NodeGroups.Delete"

	// Servers (components).
	OpServersGet    Op = "Servers.Get"
	OpServersList   Op = "Servers.List"
	OpServersCreate Op = "Servers.Create"
	OpServersUpdate Op = "Servers.Update"
	OpServersDelete Op = "Servers.Delete"

	// Well-known / discovery (public surface, no auth required).
	OpWellKnownCABundles           Op = "WellKnown.CABundles"
	OpWellKnownJWKS                Op = "WellKnown.JWKS"
	OpWellKnownOpenIDConfiguration Op = "WellKnown.OpenIDConfiguration"
)
