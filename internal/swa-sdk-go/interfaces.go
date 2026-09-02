package swa

import (
	"context"
	"iter"
)

// The interfaces below describe the method set of each resource service. They
// exist so downstream code can depend on an interface (and use the generated
// mocks under ./mocks) rather than the concrete *Client, keeping consumers
// testable. The concrete services satisfy them via the assertions at the bottom
// of this file.

// TrustDomainsAPI is the trust-domain resource surface.
type TrustDomainsAPI interface {
	Get(ctx context.Context, name string) (*TrustDomain, error)
	List(ctx context.Context, opts *ListOptions) (*TrustDomainList, error)
	All(ctx context.Context, opts *ListOptions) iter.Seq2[TrustDomain, error]
	Create(ctx context.Context, req CreateTrustDomainRequest) (*TrustDomain, error)
	Update(ctx context.Context, name string, req UpdateTrustDomainRequest) (*TrustDomain, error)
	Delete(ctx context.Context, name string) error
	Apply(ctx context.Context, req CreateTrustDomainRequest) (*TrustDomain, ApplyAction, error)
}

// ServerGroupsAPI is the server-group resource surface.
type ServerGroupsAPI interface {
	Get(ctx context.Context, trustDomain, name string) (*ServerGroup, error)
	List(ctx context.Context, trustDomain string, opts *ListOptions) (*ServerGroupList, error)
	All(ctx context.Context, trustDomain string, opts *ListOptions) iter.Seq2[ServerGroup, error]
	Create(ctx context.Context, trustDomain string, req CreateServerGroupRequest) (*ServerGroup, error)
	Update(ctx context.Context, trustDomain, name string, req UpdateServerGroupRequest) (*ServerGroup, error)
	Delete(ctx context.Context, trustDomain, name string) error
	Apply(ctx context.Context, trustDomain string, req CreateServerGroupRequest) (*ServerGroup, ApplyAction, error)
}

// NodeGroupsAPI is the node-group resource surface.
type NodeGroupsAPI interface {
	Get(ctx context.Context, trustDomain, serverGroup, name string) (*NodeGroup, error)
	List(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) (*NodeGroupList, error)
	All(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) iter.Seq2[NodeGroup, error]
	Create(ctx context.Context, trustDomain, serverGroup string, req NodeGroupCreateRequest) (*NodeGroup, error)
	Update(ctx context.Context, trustDomain, serverGroup, name string, req NodeGroupUpdateRequest) (*NodeGroup, error)
	Delete(ctx context.Context, trustDomain, serverGroup, name string) error
	Apply(ctx context.Context, trustDomain, serverGroup string, req NodeGroupCreateRequest) (*NodeGroup, ApplyAction, error)
}

// ServersAPI is the server (component) resource surface.
type ServersAPI interface {
	Get(ctx context.Context, trustDomain, serverGroup, name string) (*Server, error)
	List(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) (*ServerList, error)
	All(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) iter.Seq2[Server, error]
	Create(ctx context.Context, trustDomain, serverGroup string, req CreateServerRequest) (*CreateServerResponse, error)
	Update(ctx context.Context, trustDomain, serverGroup, name string, req UpdateServerRequest) (*Server, error)
	Delete(ctx context.Context, trustDomain, serverGroup, name string) error
	Apply(ctx context.Context, trustDomain, serverGroup string, req CreateServerRequest) (*Server, ApplyAction, error)
}

// WellKnownAPI is the public discovery surface.
type WellKnownAPI interface {
	CABundles(ctx context.Context, trustDomain string, format ...CABundleFormat) (*CABundle, error)
	JWKS(ctx context.Context, trustDomain string) (*JWKS, error)
	OpenIDConfiguration(ctx context.Context, trustDomain string) (*OpenIDConfiguration, error)
}

// ManagementAPI is the control-plane management surface: trust domains, server
// groups, node groups, servers, and the public discovery endpoints. It is the
// surface the Terraform provider and admin tooling consume, and corresponds to
// the main SWA OpenAPI spec.
type ManagementAPI interface {
	TrustDomains() TrustDomainsAPI
	ServerGroups() ServerGroupsAPI
	NodeGroups() NodeGroupsAPI
	Servers() ServersAPI
	WellKnown() WellKnownAPI
}

// API is the full resource surface of the SWA API, aggregating
// every per-resource service accessor. *Client satisfies it directly, so
// consumers can depend on swa.API instead of the concrete *Client and drop in a
// test double (see the swatest package) without writing their own adapter.
type API interface {
	ManagementAPI
}

// Compile-time assertions that the concrete services implement their interfaces
// and that *Client implements the aggregate API.
var (
	_ TrustDomainsAPI = (*TrustDomainsService)(nil)
	_ ServerGroupsAPI = (*ServerGroupsService)(nil)
	_ NodeGroupsAPI   = (*NodeGroupsService)(nil)
	_ ServersAPI      = (*ServersService)(nil)
	_ WellKnownAPI    = (*WellKnownService)(nil)
	_ ManagementAPI   = (*Client)(nil)
	_ API             = (*Client)(nil)
)
