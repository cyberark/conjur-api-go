package swafake

import (
	"sync"
	"time"

	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake/internal/serverapi/swa"
)

// DefaultGCPAttestationAudience mirrors the audience the control plane stores
// for a GCP service-account attestation configuration when the caller omits
// audiences. The fake applies it so responses match the real server, letting
// the SDK's declarative Apply round-trip without a perpetual diff.
const DefaultGCPAttestationAudience = "urn:panw:swa"

// store is the fake's in-memory state. All access is guarded by mu. Resources
// are keyed by their (scoped) name to mirror the API's uniqueness rules.
type store struct {
	mu sync.RWMutex

	// trustDomains is keyed by trust-domain name.
	trustDomains map[string]swaapi.TrustDomainResponse
	// serverGroups is keyed by trust-domain name, then server-group name.
	serverGroups map[string]map[string]swaapi.ServerGroupResponse
	// nodeGroups is keyed by trust domain, server group, then node-group name.
	nodeGroups map[string]map[string]map[string]swaapi.NodeGroupResponse
	// servers is keyed by trust domain, server group, then server name.
	servers map[string]map[string]map[string]swaapi.ServerResponse

	// bundles holds uploaded or seeded CA bundles (DER-encoded).
	bundles [][]byte
}

func newStore() *store {
	return &store{
		trustDomains: map[string]swaapi.TrustDomainResponse{},
		serverGroups: map[string]map[string]swaapi.ServerGroupResponse{},
		nodeGroups:   map[string]map[string]map[string]swaapi.NodeGroupResponse{},
		servers:      map[string]map[string]map[string]swaapi.ServerResponse{},
	}
}

// reset clears all state back to empty.
func (s *store) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trustDomains = map[string]swaapi.TrustDomainResponse{}
	s.serverGroups = map[string]map[string]swaapi.ServerGroupResponse{}
	s.nodeGroups = map[string]map[string]map[string]swaapi.NodeGroupResponse{}
	s.servers = map[string]map[string]map[string]swaapi.ServerResponse{}
	s.bundles = nil
}

// resolveTrustDomain builds the stored trust-domain representation from a create
// request, applying the same server-side defaults the real control plane would.
// base is the fake's externally-visible base URL (e.g. "http://127.0.0.1:PORT"),
// used to compute discovery endpoints.
func resolveTrustDomain(req swaapi.CreateTrustDomainRequest, base string, createdAt time.Time) swaapi.TrustDomainResponse {
	jwt := swaapi.JWTConfiguration{
		SignatureAlgorithm: swaapi.JWTConfigurationSignatureAlgorithmES256,
		SigningKeyType:     swaapi.JWTConfigurationSigningKeyTypeECP256,
		SigningKeyTtl:      86400,
		TokenTtl:           300,
		DiscoveryEndpoints: swaapi.DiscoveryEndpoints{
			JwksUri:          base + "/api/swa/trust-domains/" + req.Name + "/.well-known/jwks",
			OidcDiscoveryUrl: base + "/api/swa/trust-domains/" + req.Name + "/.well-known/openid-configuration",
		},
	}
	if in := req.Jwt; in != nil {
		if in.SignatureAlgorithm != nil {
			jwt.SignatureAlgorithm = swaapi.JWTConfigurationSignatureAlgorithm(*in.SignatureAlgorithm)
		}
		if in.SigningKeyType != nil {
			jwt.SigningKeyType = swaapi.JWTConfigurationSigningKeyType(*in.SigningKeyType)
		}
		if in.SigningKeyTtl != nil {
			jwt.SigningKeyTtl = *in.SigningKeyTtl
		}
		if in.TokenTtl != nil {
			jwt.TokenTtl = *in.TokenTtl
		}
	}
	x509 := swaapi.X509Configuration{WorkloadTtl: 3600}
	if req.X509 != nil && req.X509.WorkloadTtl != nil {
		x509.WorkloadTtl = *req.X509.WorkloadTtl
	}
	return swaapi.TrustDomainResponse{
		Name:      req.Name,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		Jwt:       jwt,
		X509:      x509,
	}
}

// applyGCPAudienceDefault normalizes an attestation configuration the way the
// server does: a GCP service-account block with no audiences gets the default
// audience filled in, so responses are directly comparable to desired state.
func applyGCPAudienceDefault(a *swaapi.AttestationConfiguration) {
	if a == nil || a.GcpServiceAccount == nil {
		return
	}
	if a.GcpServiceAccount.Audiences == nil || len(*a.GcpServiceAccount.Audiences) == 0 {
		def := []string{DefaultGCPAttestationAudience}
		a.GcpServiceAccount.Audiences = &def
	}
}

// defaultWorkloadConfiguration returns the workload configuration the server
// derives from a workload type when the caller supplies none (or an empty
// object, which the API treats as "reset to defaults").
func defaultWorkloadConfiguration(wt swaapi.NodeGroupResponseWorkloadType) swaapi.WorkloadConfiguration {
	tmpl := "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .unix_username }}"
	if wt == swaapi.NodeGroupResponseWorkloadTypeKubernetes {
		tmpl = "spiffe://{{ .trustdomain }}/{{ .nodegroup }}/{{ .k8s_namespace }}/{{ .k8s_service_account }}"
	}
	return swaapi.WorkloadConfiguration{SpiffeIdTemplate: &tmpl}
}

// normalizeWorkloadConfiguration applies reset-to-defaults semantics: a nil or
// empty (present-but-all-fields-unset) configuration is replaced with the
// workload-type defaults.
func normalizeWorkloadConfiguration(wc *swaapi.WorkloadConfiguration, wt swaapi.NodeGroupResponseWorkloadType) swaapi.WorkloadConfiguration {
	if wc == nil || (wc.SpiffeIdTemplate == nil && wc.WorkloadRegistrationPolicies == nil) {
		return defaultWorkloadConfiguration(wt)
	}
	out := *wc
	if out.SpiffeIdTemplate == nil || *out.SpiffeIdTemplate == "" {
		def := defaultWorkloadConfiguration(wt)
		out.SpiffeIdTemplate = def.SpiffeIdTemplate
	}
	return out
}
