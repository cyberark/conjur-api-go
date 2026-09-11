// Package swa implements docs/adr/0001-swa-sdk-integration.md: conjur-api-go
// owns a stable interface and set of data-type aliases over the (temporarily
// internal/) SWA SDK, so that swapping the internal copy for the real public
// module later only changes an import path in this package, never a type
// identity consumers depend on.
//
// Obtain a Client via conjurapi.ClientV2.SWA().
package swa

import (
	"strings"

	internalswa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

// Client is the control-plane surface for Secure Workload Access (SWA)
// resources: trust domains, server groups, node groups, servers, and the
// public discovery ("well-known") endpoints. Obtain one via
// conjurapi.ClientV2.SWA().
//
// This is a type alias, not a new interface: the concrete value returned by
// SWA() satisfies it structurally with no adapter code. Only the identity of
// the alias is owned by conjur-api-go.
type Client = internalswa.ManagementAPI

// TrustDomainsAPI is the trust-domain resource surface of Client.
type TrustDomainsAPI = internalswa.TrustDomainsAPI

// ServerGroupsAPI is the server-group resource surface of Client.
type ServerGroupsAPI = internalswa.ServerGroupsAPI

// NodeGroupsAPI is the node-group resource surface of Client.
type NodeGroupsAPI = internalswa.NodeGroupsAPI

// ServersAPI is the server (component) resource surface of Client.
type ServersAPI = internalswa.ServersAPI

// WellKnownAPI is the public discovery ("well-known") surface of Client.
type WellKnownAPI = internalswa.WellKnownAPI

// ListOptions controls a single page of a list request. The zero value (or
// nil) accepts the server defaults.
type ListOptions = internalswa.ListOptions

// ApplyAction reports what an Apply call did to converge a resource.
type ApplyAction = internalswa.ApplyAction

// Apply actions.
const (
	ApplyActionCreated = internalswa.ApplyActionCreated
	ApplyActionUpdated = internalswa.ApplyActionUpdated
)

// ---- Trust domains --------------------------------------------------------

// TrustDomain is a returned SWA trust domain.
type TrustDomain = internalswa.TrustDomain

// TrustDomainList is a page of trust domains.
type TrustDomainList = internalswa.TrustDomainList

// CreateTrustDomainRequest is the body for creating a trust domain.
type CreateTrustDomainRequest = internalswa.CreateTrustDomainRequest

// UpdateTrustDomainRequest is the body for updating a trust domain.
type UpdateTrustDomainRequest = internalswa.UpdateTrustDomainRequest

// JWTConfiguration is the resolved JWT configuration on a trust domain.
type JWTConfiguration = internalswa.JWTConfiguration

// JWTConfigurationInput configures JWT settings when creating a trust domain.
type JWTConfigurationInput = internalswa.JWTConfigurationInput

// UpdateJWTConfigurationInput configures JWT settings when updating.
type UpdateJWTConfigurationInput = internalswa.UpdateJWTConfigurationInput

// X509Configuration is the resolved X.509 configuration on a trust domain.
type X509Configuration = internalswa.X509Configuration

// X509ConfigurationInput configures X.509 settings when creating a trust domain.
type X509ConfigurationInput = internalswa.X509ConfigurationInput

// UpdateX509ConfigurationInput configures X.509 settings when updating.
type UpdateX509ConfigurationInput = internalswa.UpdateX509ConfigurationInput

// UpdateSignatureAlgorithm is the JWT signature algorithm when updating a trust domain.
type UpdateSignatureAlgorithm = internalswa.UpdateSignatureAlgorithm

// UpdateSigningKeyType is the JWT signing key type when updating a trust domain.
type UpdateSigningKeyType = internalswa.UpdateSigningKeyType

// DiscoveryEndpoints holds the OIDC/JWKS discovery URLs for a trust domain.
type DiscoveryEndpoints = internalswa.DiscoveryEndpoints

// ---- Server groups ---------------------------------------------------------

// ServerGroup is a returned SWA server group.
type ServerGroup = internalswa.ServerGroup

// ServerGroupList is a page of server groups.
type ServerGroupList = internalswa.ServerGroupList

// CreateServerGroupRequest is the body for creating a server group.
type CreateServerGroupRequest = internalswa.CreateServerGroupRequest

// UpdateServerGroupRequest is the body for updating a server group.
type UpdateServerGroupRequest = internalswa.UpdateServerGroupRequest

// AttestationConfiguration is the node-attestation configuration for a group.
type AttestationConfiguration = internalswa.AttestationConfiguration

// K8sPsatConfigurationInput configures Kubernetes PSAT node attestation.
type K8sPsatConfigurationInput = internalswa.K8sPsatConfigurationInput

// K8sPsatCluster is a single Kubernetes PSAT cluster configuration.
type K8sPsatCluster = internalswa.K8sPsatCluster

// X509PopConfigurationInput configures X.509 proof-of-possession attestation.
type X509PopConfigurationInput = internalswa.X509PopConfigurationInput

// GcpServiceAccountAttestationConfiguration configures GCP service-account attestation.
type GcpServiceAccountAttestationConfiguration = internalswa.GcpServiceAccountAttestationConfiguration

// GeminiEnterpriseAttestationConfiguration configures Gemini Enterprise agent identity attestation.
type GeminiEnterpriseAttestationConfiguration = internalswa.GeminiEnterpriseAttestationConfiguration

// AwsIidAttestationConfiguration configures EC2 Instance Identity Document (aws_iid) node attestation.
type AwsIidAttestationConfiguration = internalswa.AwsIidAttestationConfiguration

// AwsIidVerifyOrganizationConfiguration configures validation that attesting nodes belong to an AWS Organization.
type AwsIidVerifyOrganizationConfiguration = internalswa.AwsIidVerifyOrganizationConfiguration

// DeprecatedAttestationConfiguration is the legacy node-attestation configuration
// (x509pop and k8s_psat only). Prefer AttestationConfiguration.
type DeprecatedAttestationConfiguration = internalswa.DeprecatedAttestationConfiguration

// ---- Node groups -------------------------------------------------------------

// NodeGroup is a returned SWA node group.
type NodeGroup = internalswa.NodeGroup

// NodeGroupList is a page of node groups.
type NodeGroupList = internalswa.NodeGroupList

// NodeGroupCreateRequest is the body for creating a node group.
type NodeGroupCreateRequest = internalswa.NodeGroupCreateRequest

// NodeGroupUpdateRequest is the body for updating a node group.
type NodeGroupUpdateRequest = internalswa.NodeGroupUpdateRequest

// WorkloadConfiguration controls workload identity issuance for a node group.
type WorkloadConfiguration = internalswa.WorkloadConfiguration

// WorkloadType is the workload type of a node group (e.g. "unix", "kubernetes").
type WorkloadType = internalswa.WorkloadType

// ---- Servers ------------------------------------------------------------------

// Server is a returned SWA server (component).
type Server = internalswa.Server

// ServerList is a page of servers.
type ServerList = internalswa.ServerList

// CreateServerRequest is the body for registering a server.
type CreateServerRequest = internalswa.CreateServerRequest

// CreateServerResponse is returned when a server is registered.
type CreateServerResponse = internalswa.CreateServerResponse

// UpdateServerRequest is the body for updating a server's authenticator.
type UpdateServerRequest = internalswa.UpdateServerRequest

// CreateServerAuthentication is the authentication block on server creation.
type CreateServerAuthentication = internalswa.CreateServerAuthentication

// CreateServerAuthenticationType is the authentication type on server creation (e.g. "JWT").
type CreateServerAuthenticationType = internalswa.CreateServerAuthenticationType

// CreateServerAuthenticationData is the polymorphic authentication data union on
// server creation. Populate it via its From*/Merge* helpers (e.g.
// FromCreateServerJWTAuthenticationData).
type CreateServerAuthenticationData = internalswa.CreateServerAuthenticationData

// CreateServerJWTAuthenticationData is the JWT authenticator payload for server creation.
type CreateServerJWTAuthenticationData = internalswa.CreateServerJWTAuthenticationData

// ServerAuthentication is the authentication configuration on a server.
type ServerAuthentication = internalswa.ServerAuthentication

// ---- Discovery / well-known -----------------------------------------------

// CABundle is a CA bundle response (PEM or DER form).
type CABundle = internalswa.CABundle

// JWKS is a JSON Web Key Set document.
type JWKS = internalswa.JWKS

// JWK is a single JSON Web Key.
type JWK = internalswa.JWK

// OpenIDConfiguration is the OpenID Connect discovery document.
type OpenIDConfiguration = internalswa.OpenIDConfiguration

// CABundleFormat selects the encoding of a CA bundle response.
type CABundleFormat = internalswa.CABundleFormat

// CA bundle formats.
const (
	CABundleFormatDER = internalswa.CABundleFormatDER
	CABundleFormatPEM = internalswa.CABundleFormatPEM
)

// ---- Enumerations (create-time) -------------------------------------------

// SigningKeyType is the JWT signing key type for a trust domain.
type SigningKeyType = internalswa.SigningKeyType

// Signing key types.
const (
	SigningKeyTypeECP256  = internalswa.SigningKeyTypeECP256
	SigningKeyTypeECP384  = internalswa.SigningKeyTypeECP384
	SigningKeyTypeECP521  = internalswa.SigningKeyTypeECP521
	SigningKeyTypeRSA2048 = internalswa.SigningKeyTypeRSA2048
	SigningKeyTypeRSA4096 = internalswa.SigningKeyTypeRSA4096
)

// SignatureAlgorithm is the JWT signature algorithm for a trust domain.
type SignatureAlgorithm = internalswa.SignatureAlgorithm

// Signature algorithms.
const (
	SignatureAlgorithmES256 = internalswa.SignatureAlgorithmES256
	SignatureAlgorithmES384 = internalswa.SignatureAlgorithmES384
	SignatureAlgorithmES512 = internalswa.SignatureAlgorithmES512
	SignatureAlgorithmRS256 = internalswa.SignatureAlgorithmRS256
	SignatureAlgorithmRS384 = internalswa.SignatureAlgorithmRS384
	SignatureAlgorithmRS512 = internalswa.SignatureAlgorithmRS512
)

// ---- Errors -----------------------------------------------------------------
//
// Client methods return plain `error`. The underlying SWA SDK's typed error
// surface (swaerrors.APIError, status predicates like IsNotFound) is not
// re-exported here: it lives under internal/ during the temporary copy period,
// so callers can only get typed error branching once the public swa-sdk-go
// module ships and can be depended on directly — that's a value-add worth
// waiting for, not one worth building bespoke aliasing plumbing for now absent
// a concrete caller need.
//
// Construction lives in conjurapi.ClientV2.SWA(), the only place that builds a
// Client: it needs conjur-api-go's own unexported *http.Client and auth
// wiring, so there's nothing for this package to usefully re-export beyond the
// Client type itself and the resource types above.
//
// UserMessage is the one concrete caller need that surfaced (conjur-cli-go
// needs to print a clean, user-facing line rather than the raw wrapped error):
// it uses the internal error types itself, without exposing them.

// UserMessage returns the part of err meant for a CLI/UI to display: the
// violation text for a client-side *ValidationError, or the API's message for
// a server-side *APIError, without the "swa: <Op>: " prefix or the trailing
// "[status=... request_id=...]" suffix that Error() adds for logs/support.
//
// If err is not a recognized SWA error type, its Error() string is returned
// unchanged.
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	if vErr, ok := swaerrors.AsValidationError(err); ok {
		parts := make([]string, len(vErr.Violations))
		for i, v := range vErr.Violations {
			parts[i] = v.String()
		}
		return strings.Join(parts, "; ")
	}
	if apiErr, ok := swaerrors.AsAPIError(err); ok && apiErr.Message != "" {
		return apiErr.Message
	}
	return err.Error()
}
