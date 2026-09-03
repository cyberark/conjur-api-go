package swa

import (
	"context"
	"iter"
	"net/http"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// ServerGroupsService provides access to the SWA server-group resource. Server
// groups are scoped to a trust domain, so every method takes the trust domain
// name as its first argument.
type ServerGroupsService struct {
	client *Client
}

// Get returns the named server group within a trust domain.
func (s *ServerGroupsService) Get(ctx context.Context, trustDomain, name string) (*ServerGroup, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetServerGroup(ctx, trustDomain, name, &swaapi.GetServerGroupParams{Accept: acceptV2})
	})
	if err != nil {
		return nil, err
	}
	var out ServerGroup
	if err := HandleResponse(swaerrors.OpServerGroupsGet, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns a single page of server groups within a trust domain.
func (s *ServerGroupsService) List(ctx context.Context, trustDomain string, opts *ListOptions) (*ServerGroupList, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetServerGroups(ctx, trustDomain, &swaapi.GetServerGroupsParams{
			Limit:  opts.limit(),
			Offset: opts.offset(),
			Accept: acceptV2,
		})
	})
	if err != nil {
		return nil, err
	}
	var out ServerGroupList
	if err := HandleResponse(swaerrors.OpServerGroupsList, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// All returns an iterator that transparently paginates over every server group
// in a trust domain.
func (s *ServerGroupsService) All(ctx context.Context, trustDomain string, opts *ListOptions) iter.Seq2[ServerGroup, error] {
	var pageSize int32
	if opts != nil {
		pageSize = opts.Limit
	}
	return paginate(ctx, pageSize, func(ctx context.Context, limit, offset int32) ([]ServerGroup, error) {
		page, err := s.List(ctx, trustDomain, &ListOptions{Limit: limit, Offset: offset})
		if err != nil {
			return nil, err
		}
		return page.ServerGroups, nil
	})
}

// Create creates a server group in the trust domain. The request is validated
// client-side before it is sent; an invalid request yields a *swaerrors.ValidationError.
func (s *ServerGroupsService) Create(ctx context.Context, trustDomain string, req CreateServerGroupRequest) (*ServerGroup, error) {
	if err := ValidateCreateServerGroupRequest(req); err != nil {
		return nil, err
	}
	resp, err := s.client.Execute(ctx, false, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PostServerGroup(ctx, trustDomain, &swaapi.PostServerGroupParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out ServerGroup
	if err := HandleResponse(swaerrors.OpServerGroupsCreate, resp, &out, []int{http.StatusCreated, http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update patches a server group.
func (s *ServerGroupsService) Update(ctx context.Context, trustDomain, name string, req UpdateServerGroupRequest) (*ServerGroup, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PatchServerGroup(ctx, trustDomain, name, &swaapi.PatchServerGroupParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out ServerGroup
	if err := HandleResponse(swaerrors.OpServerGroupsUpdate, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes a server group and all servers within it.
func (s *ServerGroupsService) Delete(ctx context.Context, trustDomain, name string) error {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.DeleteServerGroup(ctx, trustDomain, name, &swaapi.DeleteServerGroupParams{Accept: acceptV2})
	})
	if err != nil {
		return err
	}
	return HandleResponse(swaerrors.OpServerGroupsDelete, resp, nil, []int{http.StatusNoContent, http.StatusOK})
}

// Apply ensures a server group matching req exists within the trust domain,
// creating it when absent and updating it to match when present. Because the
// update sends the full desired attestation configuration, attestation sub-types
// dropped from req are cleared server-side. See the reconcile notes in apply.go.
func (s *ServerGroupsService) Apply(ctx context.Context, trustDomain string, req CreateServerGroupRequest) (*ServerGroup, ApplyAction, error) {
	if err := ValidateCreateServerGroupRequest(req); err != nil {
		return nil, "", err
	}
	_, err := s.Get(ctx, trustDomain, req.Name)
	switch {
	case err == nil:
		sg, uErr := s.Update(ctx, trustDomain, req.Name, toUpdateServerGroupRequest(req))
		if uErr != nil {
			return nil, "", uErr
		}
		return sg, ApplyActionUpdated, nil
	case swaerrors.IsNotFound(err):
		sg, cErr := s.Create(ctx, trustDomain, req)
		if cErr != nil {
			return nil, "", cErr
		}
		return sg, ApplyActionCreated, nil
	default:
		return nil, "", err
	}
}

// toUpdateServerGroupRequest projects a create request onto the server-group
// update request. The name is immutable and therefore not carried over. The
// deprecated node_attestation field is intentionally not propagated — the SDK
// only supports the current attestation field.
func toUpdateServerGroupRequest(req CreateServerGroupRequest) UpdateServerGroupRequest {
	return UpdateServerGroupRequest{
		Description: req.Description,
		Attestation: req.Attestation,
	}
}

// ValidateCreateServerGroupRequest checks a server-group create request. Besides
// the name rule, the server requires at least one attestation object in the
// attestation field. (The legacy node_attestation field is deprecated and not
// supported by the SDK.)
func ValidateCreateServerGroupRequest(req CreateServerGroupRequest) error {
	var v []swaerrors.FieldViolation
	resourceNameRule.validate("name", req.Name, &v)
	if !attestationConfigured(req.Attestation) {
		v = append(v, swaerrors.FieldViolation{
			Field:   "attestation",
			Message: "at least one attestation method (x509pop, k8s_psat, gcp_service_account, gemini_enterprise, or aws_iid) must be configured",
		})
	}
	return swaerrors.NewValidationError(swaerrors.OpServerGroupsCreate, v)
}

// attestationConfigured reports whether at least one attestation object is set.
func attestationConfigured(a *AttestationConfiguration) bool {
	return a != nil && (a.X509pop != nil || a.K8sPsat != nil || a.GcpServiceAccount != nil || a.GeminiEnterprise != nil || a.AwsIid != nil)
}
