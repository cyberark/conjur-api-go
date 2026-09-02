package swa

import (
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// This file re-exports the generated request/response models under clean,
// stable names in the public package. Using type aliases keeps the models in
// perfect sync with the OpenAPI spec (they ARE the generated types) while
// letting consumers depend only on this package, never on internal/gen.

// ---- Trust domains -------------------------------------------------------

// TrustDomain is a returned SWA trust domain.
type TrustDomain = swaapi.TrustDomainResponse

// TrustDomainList is a page of trust domains.
type TrustDomainList = swaapi.TrustDomainListResponse

// CreateTrustDomainRequest is the body for creating a trust domain.
type CreateTrustDomainRequest = swaapi.CreateTrustDomainRequest

// UpdateTrustDomainRequest is the body for updating a trust domain.
type UpdateTrustDomainRequest = swaapi.UpdateTrustDomainRequest

// JWTConfiguration is the resolved JWT configuration on a trust domain.
type JWTConfiguration = swaapi.JWTConfiguration

// JWTConfigurationInput configures JWT settings when creating a trust domain.
type JWTConfigurationInput = swaapi.JWTConfigurationInput

// UpdateJWTConfigurationInput configures JWT settings when updating.
type UpdateJWTConfigurationInput = swaapi.UpdateJWTConfigurationInput

// X509Configuration is the resolved X.509 configuration on a trust domain.
type X509Configuration = swaapi.X509Configuration

// X509ConfigurationInput configures X.509 settings when creating a trust domain.
type X509ConfigurationInput = swaapi.X509ConfigurationInput

// UpdateX509ConfigurationInput configures X.509 settings when updating.
type UpdateX509ConfigurationInput = swaapi.UpdateX509ConfigurationInput

// UpdateSignatureAlgorithm is the JWT signature algorithm when updating a trust domain.
type UpdateSignatureAlgorithm = swaapi.UpdateJWTConfigurationInputSignatureAlgorithm

// UpdateSigningKeyType is the JWT signing key type when updating a trust domain.
type UpdateSigningKeyType = swaapi.UpdateJWTConfigurationInputSigningKeyType

// DiscoveryEndpoints holds the OIDC/JWKS discovery URLs for a trust domain.
type DiscoveryEndpoints = swaapi.DiscoveryEndpoints

// ---- Server groups -------------------------------------------------------

// ServerGroup is a returned SWA server group.
type ServerGroup = swaapi.ServerGroupResponse

// ServerGroupList is a page of server groups.
type ServerGroupList = swaapi.ServerGroupListResponse

// CreateServerGroupRequest is the body for creating a server group.
type CreateServerGroupRequest = swaapi.CreateServerGroupRequest

// UpdateServerGroupRequest is the body for updating a server group.
type UpdateServerGroupRequest = swaapi.UpdateServerGroupRequest

// AttestationConfiguration is the node-attestation configuration for a group.
type AttestationConfiguration = swaapi.AttestationConfiguration

// K8sPsatConfigurationInput configures Kubernetes PSAT node attestation.
type K8sPsatConfigurationInput = swaapi.K8sPsatConfigurationInput

// K8sPsatCluster is a single Kubernetes PSAT cluster configuration.
type K8sPsatCluster = swaapi.K8sPsatCluster

// X509PopConfigurationInput configures X.509 proof-of-possession attestation.
type X509PopConfigurationInput = swaapi.X509PopConfigurationInput

// GcpServiceAccountAttestationConfiguration configures GCP service-account attestation.
type GcpServiceAccountAttestationConfiguration = swaapi.GcpServiceAccountAttestationConfiguration

// GeminiEnterpriseAttestationConfiguration configures Gemini Enterprise agent identity attestation.
type GeminiEnterpriseAttestationConfiguration = swaapi.GeminiEnterpriseAttestationConfiguration

// AwsIidAttestationConfiguration configures EC2 Instance Identity Document (aws_iid) node attestation.
type AwsIidAttestationConfiguration = swaapi.AwsIidAttestationConfiguration

// AwsIidVerifyOrganizationConfiguration configures validation that attesting nodes belong to an AWS Organization.
type AwsIidVerifyOrganizationConfiguration = swaapi.AwsIidVerifyOrganizationConfiguration

// AwsIidAttestationConfigurationPartition is the AWS partition for aws_iid attestation.
type AwsIidAttestationConfigurationPartition = swaapi.AwsIidAttestationConfigurationPartition

// AWS partitions for aws_iid attestation.
const (
	AwsIidAttestationConfigurationPartitionAws      AwsIidAttestationConfigurationPartition = swaapi.Aws
	AwsIidAttestationConfigurationPartitionAwsCn    AwsIidAttestationConfigurationPartition = swaapi.AwsCn
	AwsIidAttestationConfigurationPartitionAwsUsGov AwsIidAttestationConfigurationPartition = swaapi.AwsUsGov
)

// DeprecatedAttestationConfiguration is the legacy node-attestation configuration
// (x509pop and k8s_psat only). Prefer AttestationConfiguration.
type DeprecatedAttestationConfiguration = swaapi.DeprecatedAttestationConfiguration

// ---- Node groups ---------------------------------------------------------

// NodeGroup is a returned SWA node group.
type NodeGroup = swaapi.NodeGroupResponse

// NodeGroupList is a page of node groups.
type NodeGroupList = swaapi.NodeGroupListResponse

// NodeGroupCreateRequest is the body for creating a node group.
type NodeGroupCreateRequest = swaapi.NodeGroupCreateRequest

// NodeGroupUpdateRequest is the body for updating a node group.
type NodeGroupUpdateRequest = swaapi.NodeGroupUpdateRequest

// WorkloadConfiguration controls workload identity issuance for a node group.
type WorkloadConfiguration = swaapi.WorkloadConfiguration

// WorkloadType is the workload type of a node group (e.g. "unix", "kubernetes").
type WorkloadType = swaapi.NodeGroupCreateRequestWorkloadType

// ---- Servers -------------------------------------------------------------

// Server is a returned SWA server (component).
type Server = swaapi.ServerResponse

// ServerList is a page of servers.
type ServerList = swaapi.ServerListResponse

// CreateServerRequest is the body for registering a server.
type CreateServerRequest = swaapi.CreateServerRequest

// CreateServerResponse is returned when a server is registered.
type CreateServerResponse = swaapi.CreateServerResponse

// UpdateServerRequest is the body for updating a server's authenticator.
type UpdateServerRequest = swaapi.UpdateServerRequest

// CreateServerAuthentication is the authentication block on server creation.
type CreateServerAuthentication = swaapi.CreateServerAuthentication

// CreateServerAuthenticationType is the authentication type on server creation (e.g. "JWT").
type CreateServerAuthenticationType = swaapi.CreateServerAuthenticationType

// CreateServerAuthenticationData is the polymorphic authentication data union on
// server creation. Populate it via its From*/Merge* helpers (e.g.
// FromCreateServerJWTAuthenticationData).
type CreateServerAuthenticationData = swaapi.CreateServerAuthentication_Data

// CreateServerJWTAuthenticationData is the JWT authenticator payload for server creation.
type CreateServerJWTAuthenticationData = swaapi.CreateServerJWTAuthenticationData

// ServerAuthentication is the authentication configuration on a server.
type ServerAuthentication = swaapi.ServerAuthentication

// ---- Discovery / well-known ---------------------------------------------

// CABundle is a CA bundle response (PEM or DER form).
type CABundle = swaapi.CABundleResponse

// JWKS is a JSON Web Key Set document.
type JWKS = swaapi.JWKS

// JWK is a single JSON Web Key.
type JWK = swaapi.JWK

// OpenIDConfiguration is the OpenID Connect discovery document.
type OpenIDConfiguration = swaapi.OpenIDConfiguration

// CABundleFormat selects the encoding of a CA bundle response.
type CABundleFormat = swaapi.GetCaBundlesParamsFormat

// CA bundle formats.
const (
	CABundleFormatDER CABundleFormat = swaapi.Der
	CABundleFormatPEM CABundleFormat = swaapi.Pem
)

// ---- Enumerations (create-time) -----------------------------------------

// SigningKeyType is the JWT signing key type for a trust domain.
type SigningKeyType = swaapi.JWTConfigurationInputSigningKeyType

// Signing key types.
const (
	SigningKeyTypeECP256  SigningKeyType = swaapi.JWTConfigurationInputSigningKeyTypeECP256
	SigningKeyTypeECP384  SigningKeyType = swaapi.JWTConfigurationInputSigningKeyTypeECP384
	SigningKeyTypeECP521  SigningKeyType = swaapi.JWTConfigurationInputSigningKeyTypeECP521
	SigningKeyTypeRSA2048 SigningKeyType = swaapi.JWTConfigurationInputSigningKeyTypeRSA2048
	SigningKeyTypeRSA4096 SigningKeyType = swaapi.JWTConfigurationInputSigningKeyTypeRSA4096
)

// SignatureAlgorithm is the JWT signature algorithm for a trust domain.
type SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithm

// Signature algorithms.
const (
	SignatureAlgorithmES256 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmES256
	SignatureAlgorithmES384 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmES384
	SignatureAlgorithmES512 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmES512
	SignatureAlgorithmRS256 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmRS256
	SignatureAlgorithmRS384 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmRS384
	SignatureAlgorithmRS512 SignatureAlgorithm = swaapi.JWTConfigurationInputSignatureAlgorithmRS512
)
