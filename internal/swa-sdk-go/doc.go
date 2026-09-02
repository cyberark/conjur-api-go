// Package swa is the official Go SDK for the SWA (Secure Workload Access) API.
// It provides an ergonomic, hand-written facade over the
// oapi-codegen-generated clients for the SWA API surfaces:
//
//   - trust domains, server groups, node groups, servers, and public discovery endpoints.
//
// # Design
//
// The SDK follows the resource-service layout popularised by the AWS and GCP Go
// SDKs and Kubernetes client-go: a single Client is the entry point, and each
// API surface is reached through an accessor that returns a typed service. Every
// method is context-first, takes typed request structs, returns typed models,
// and reports failures as a single *swaerrors.APIError with status-based
// predicates (swaerrors.IsNotFound, swaerrors.IsConflict, and so on) from the
// swaerrors subpackage.
//
// The generated low-level clients live under internal/gen and are never exposed;
// they are regenerated in-place from the canonical OpenAPI specs that ship with
// the service, so the client can never drift from the server contract.
//
// # Quick start
//
//	client, err := swa.NewClient(
//	    swa.WithBaseURL("https://example.secretsmgr.cyberark.cloud"),
//	    swa.WithConjurToken(token),
//	)
//	if err != nil {
//	    return err
//	}
//
//	td, err := client.TrustDomains().Get(ctx, "prod.example.com")
//	if swaerrors.IsNotFound(err) {
//	    // handle missing trust domain
//	}
//
// # Authentication
//
// The core module is dependency-light and knows nothing about how tokens are
// minted. Simple cases use WithConjurToken or WithBearerToken. For refreshing
// credentials, supply a TokenSource (WithTokenSource) or an authenticating
// http.RoundTripper (WithRoundTripper). Ready-made adapters live in opt-in
// sub-modules:
//
//   - auth/conjur wraps conjur-api-go for the full range of Conjur
//     authenticators (API key, JWT, OIDC, IAM, Azure, GCP, cert) with refresh.
//
// The import path's final element is "swa-sdk-go" but the
// package name is "swa"; import it with that name (or alias it) as shown above.
package swa
