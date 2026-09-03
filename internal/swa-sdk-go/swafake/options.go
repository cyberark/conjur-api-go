package swafake

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	swa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake/internal/serverapi/swa"
)

// toServerModel converts a public SDK request type into the equivalent
// echo-server model the fake's store uses. Both are generated from the same
// OpenAPI spec, so a JSON round-trip is exact; keeping the conversion here lets
// the seeding options speak the SDK's public vocabulary (swa.*) while the store
// stays on the server types.
func toServerModel[T any](in any) T {
	var out T
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, &out)
	return out
}

// Option configures a fake Server at construction time.
type Option func(*Server)

// fault is an injected error response matched against incoming requests.
type fault struct {
	method  string // empty matches any method
	path    string // substring match against the request path; empty matches any
	status  int
	code    string
	message string
}

func (f fault) matches(r *http.Request) bool {
	if f.method != "" && !strings.EqualFold(f.method, r.Method) {
		return false
	}
	if f.path != "" && !strings.Contains(r.URL.Path, f.path) {
		return false
	}
	return true
}

// WithError injects an error response for every request matching method and a
// path substring. An empty method or path matches anything. Faults are checked
// in registration order, before auth and routing, so this is the simplest way
// to exercise the SDK's error handling (swaerrors.IsNotFound, swaerrors.IsConflict, retries, ...).
func WithError(method, pathSubstring string, status int, code, message string) Option {
	return func(s *Server) {
		s.faults = append(s.faults, fault{
			method:  method,
			path:    pathSubstring,
			status:  status,
			code:    code,
			message: message,
		})
	}
}

// WithoutAuth disables the fake's Authorization-header check. By default the
// fake rejects unauthenticated requests to /api/swa (well-known excepted) with
// 401, matching the real service.
func WithoutAuth() Option {
	return func(s *Server) { s.requireAuth = false }
}

// WithToken requires that the Authorization header contain the given token
// value. By default any non-empty Authorization header is accepted.
func WithToken(token string) Option {
	return func(s *Server) { s.token = token }
}

// WithTrustDomain seeds a trust domain (with server-resolved defaults) so tests
// can start from an existing resource. jwt/x509 overrides are optional.
func WithTrustDomain(name string, mutators ...func(*swa.CreateTrustDomainRequest)) Option {
	return func(s *Server) {
		req := swa.CreateTrustDomainRequest{Name: name}
		for _, m := range mutators {
			m(&req)
		}
		srvReq := toServerModel[swaapi.CreateTrustDomainRequest](req)
		s.seeds = append(s.seeds, func(base string) {
			s.store.mu.Lock()
			defer s.store.mu.Unlock()
			s.store.trustDomains[name] = resolveTrustDomain(srvReq, base, time.Now().UTC())
		})
	}
}

// WithServerGroup seeds a server group under an (already-seeded or implicitly
// created) trust domain.
func WithServerGroup(trustDomain string, publicReq swa.CreateServerGroupRequest) Option {
	return func(s *Server) {
		req := toServerModel[swaapi.CreateServerGroupRequest](publicReq)
		s.seeds = append(s.seeds, func(base string) {
			s.store.mu.Lock()
			defer s.store.mu.Unlock()
			if _, exists := s.store.trustDomains[trustDomain]; !exists {
				s.store.trustDomains[trustDomain] = resolveTrustDomain(swaapi.CreateTrustDomainRequest{Name: trustDomain}, base, time.Now().UTC())
			}
			applyGCPAudienceDefault(req.Attestation)
			now := time.Now().UTC()
			sg := swaapi.ServerGroupResponse{
				Name:            req.Name,
				TrustDomainName: trustDomain,
				Description:     req.Description,
				Attestation:     req.Attestation,
				NodeAttestation: req.NodeAttestation,
				CreatedAt:       &now,
				UpdatedAt:       &now,
			}
			if s.store.serverGroups[trustDomain] == nil {
				s.store.serverGroups[trustDomain] = map[string]swaapi.ServerGroupResponse{}
			}
			s.store.serverGroups[trustDomain][req.Name] = sg
		})
	}
}

// WithAwsIidAttestor seeds an aws_iid node-attestation configuration onto a
// server group, creating the trust domain and/or server group first if they
// haven't already been seeded. assumeRole, partition, and verifyOrganization
// are all optional operational overlays — pass "" / nil to omit a field.
func WithAwsIidAttestor(trustDomain, serverGroup, assumeRole string, partition swa.AwsIidAttestationConfigurationPartition, verifyOrganization *swa.AwsIidVerifyOrganizationConfiguration) Option {
	return func(s *Server) {
		s.seeds = append(s.seeds, func(base string) {
			s.store.mu.Lock()
			defer s.store.mu.Unlock()
			if _, exists := s.store.trustDomains[trustDomain]; !exists {
				s.store.trustDomains[trustDomain] = resolveTrustDomain(swaapi.CreateTrustDomainRequest{Name: trustDomain}, base, time.Now().UTC())
			}
			if s.store.serverGroups[trustDomain] == nil {
				s.store.serverGroups[trustDomain] = map[string]swaapi.ServerGroupResponse{}
			}
			now := time.Now().UTC()
			sg, exists := s.store.serverGroups[trustDomain][serverGroup]
			if !exists {
				sg = swaapi.ServerGroupResponse{
					Name:            serverGroup,
					TrustDomainName: trustDomain,
					CreatedAt:       &now,
				}
			}
			if sg.Attestation == nil {
				sg.Attestation = &swaapi.AttestationConfiguration{}
			}
			awsIid := &swaapi.AwsIidAttestationConfiguration{}
			if assumeRole != "" {
				awsIid.AssumeRole = &assumeRole
			}
			if partition != "" {
				p := swaapi.AwsIidAttestationConfigurationPartition(partition)
				awsIid.Partition = &p
			}
			if verifyOrganization != nil {
				vo := toServerModel[swaapi.AwsIidVerifyOrganizationConfiguration](*verifyOrganization)
				awsIid.VerifyOrganization = &vo
			}
			sg.Attestation.AwsIid = awsIid
			sg.UpdatedAt = &now
			s.store.serverGroups[trustDomain][serverGroup] = sg
		})
	}
}
