package swa

import (
	"context"
	"net/http"

	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

// WellKnownService exposes the public discovery endpoints for a trust domain.
// These endpoints do not require authentication.
type WellKnownService struct {
	client *Client
}

// CABundles returns the CA bundles for a trust domain. The optional format
// selects DER (default) or PEM encoding.
func (s *WellKnownService) CABundles(ctx context.Context, trustDomain string, format ...CABundleFormat) (*CABundle, error) {
	params := &swaapi.GetCaBundlesParams{}
	if len(format) > 0 {
		f := format[0]
		params.Format = &f
	}
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetCaBundles(ctx, trustDomain, params)
	})
	if err != nil {
		return nil, err
	}
	var out CABundle
	if err := HandleResponse(swaerrors.OpWellKnownCABundles, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKS returns the JSON Web Key Set for a trust domain.
func (s *WellKnownService) JWKS(ctx context.Context, trustDomain string) (*JWKS, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetJwks(ctx, trustDomain)
	})
	if err != nil {
		return nil, err
	}
	var out JWKS
	if err := HandleResponse(swaerrors.OpWellKnownJWKS, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// OpenIDConfiguration returns the OpenID Connect discovery document for a trust
// domain.
func (s *WellKnownService) OpenIDConfiguration(ctx context.Context, trustDomain string) (*OpenIDConfiguration, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetOpenidConfiguration(ctx, trustDomain)
	})
	if err != nil {
		return nil, err
	}
	var out OpenIDConfiguration
	if err := HandleResponse(swaerrors.OpWellKnownOpenIDConfiguration, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}
