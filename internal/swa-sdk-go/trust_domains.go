package swa

import (
	"context"
	"iter"
	"net/http"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// acceptV2 is the required Accept header value for the SWA control-plane API.
const acceptV2 = swaapi.ApplicationxSecretsmgrV2Json

// TrustDomainsService provides access to the SWA trust-domain resource.
type TrustDomainsService struct {
	client *Client
}

// Get returns the trust domain with the given name.
func (s *TrustDomainsService) Get(ctx context.Context, name string) (*TrustDomain, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetTrustDomain(ctx, name, &swaapi.GetTrustDomainParams{Accept: acceptV2})
	})
	if err != nil {
		return nil, err
	}
	var out TrustDomain
	if err := HandleResponse(swaerrors.OpTrustDomainsGet, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns a single page of trust domains. Pass nil for server defaults.
func (s *TrustDomainsService) List(ctx context.Context, opts *ListOptions) (*TrustDomainList, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetTrustDomains(ctx, &swaapi.GetTrustDomainsParams{
			Limit:  opts.limit(),
			Offset: opts.offset(),
			Accept: acceptV2,
		})
	})
	if err != nil {
		return nil, err
	}
	var out TrustDomainList
	if err := HandleResponse(swaerrors.OpTrustDomainsList, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// All returns an iterator that transparently paginates over every trust domain.
// Iterate with range-over-func:
//
//	for td, err := range client.TrustDomains().All(ctx, nil) {
//	    if err != nil { return err }
//	    // use td
//	}
func (s *TrustDomainsService) All(ctx context.Context, opts *ListOptions) iter.Seq2[TrustDomain, error] {
	var pageSize int32
	if opts != nil {
		pageSize = opts.Limit
	}
	return paginate(ctx, pageSize, func(ctx context.Context, limit, offset int32) ([]TrustDomain, error) {
		page, err := s.List(ctx, &ListOptions{Limit: limit, Offset: offset})
		if err != nil {
			return nil, err
		}
		return page.TrustDomains, nil
	})
}

// Create registers a new trust domain. The request is validated client-side
// before it is sent; an invalid request yields a *swaerrors.ValidationError.
func (s *TrustDomainsService) Create(ctx context.Context, req CreateTrustDomainRequest) (*TrustDomain, error) {
	if err := ValidateCreateTrustDomainRequest(req); err != nil {
		return nil, err
	}
	resp, err := s.client.Execute(ctx, false, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PostTrustDomain(ctx, &swaapi.PostTrustDomainParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out TrustDomain
	if err := HandleResponse(swaerrors.OpTrustDomainsCreate, resp, &out, []int{http.StatusCreated, http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update patches an existing trust domain. The operation is idempotent.
func (s *TrustDomainsService) Update(ctx context.Context, name string, req UpdateTrustDomainRequest) (*TrustDomain, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PatchTrustDomain(ctx, name, &swaapi.PatchTrustDomainParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out TrustDomain
	if err := HandleResponse(swaerrors.OpTrustDomainsUpdate, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes a trust domain and all resources within it.
func (s *TrustDomainsService) Delete(ctx context.Context, name string) error {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.DeleteTrustDomain(ctx, name, &swaapi.DeleteTrustDomainParams{Accept: acceptV2})
	})
	if err != nil {
		return err
	}
	return HandleResponse(swaerrors.OpTrustDomainsDelete, resp, nil, []int{http.StatusNoContent, http.StatusOK})
}

// Apply ensures a trust domain matching req exists, creating it when absent and
// updating it to match when present. The desired state is validated client-side
// first (a *swaerrors.ValidationError is returned for invalid input). See the reconcile
// notes in apply.go.
func (s *TrustDomainsService) Apply(ctx context.Context, req CreateTrustDomainRequest) (*TrustDomain, ApplyAction, error) {
	if err := ValidateCreateTrustDomainRequest(req); err != nil {
		return nil, "", err
	}
	_, err := s.Get(ctx, req.Name)
	switch {
	case err == nil:
		td, uErr := s.Update(ctx, req.Name, toUpdateTrustDomainRequest(req))
		if uErr != nil {
			return nil, "", uErr
		}
		return td, ApplyActionUpdated, nil
	case swaerrors.IsNotFound(err):
		td, cErr := s.Create(ctx, req)
		if cErr != nil {
			return nil, "", cErr
		}
		return td, ApplyActionCreated, nil
	default:
		return nil, "", err
	}
}

// toUpdateTrustDomainRequest projects a create request onto the trust-domain
// update request. The name is immutable and therefore not carried over.
func toUpdateTrustDomainRequest(req CreateTrustDomainRequest) UpdateTrustDomainRequest {
	var out UpdateTrustDomainRequest
	if req.Jwt != nil {
		jwt := &UpdateJWTConfigurationInput{
			SigningKeyTtl: req.Jwt.SigningKeyTtl,
			TokenTtl:      req.Jwt.TokenTtl,
		}
		if req.Jwt.SignatureAlgorithm != nil {
			alg := UpdateSignatureAlgorithm(*req.Jwt.SignatureAlgorithm)
			jwt.SignatureAlgorithm = &alg
		}
		if req.Jwt.SigningKeyType != nil {
			kt := UpdateSigningKeyType(*req.Jwt.SigningKeyType)
			jwt.SigningKeyType = &kt
		}
		out.Jwt = jwt
	}
	if req.X509 != nil && req.X509.WorkloadTtl != nil {
		out.X509 = &UpdateX509ConfigurationInput{WorkloadTtl: *req.X509.WorkloadTtl}
	}
	return out
}

// ValidateCreateTrustDomainRequest checks a trust-domain create request against
// the server's contract. It returns a *swaerrors.ValidationError or nil.
func ValidateCreateTrustDomainRequest(req CreateTrustDomainRequest) error {
	var v []swaerrors.FieldViolation
	resourceNameRule.validate("name", req.Name, &v)
	return swaerrors.NewValidationError(swaerrors.OpTrustDomainsCreate, v)
}
