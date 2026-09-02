package swa

import (
	"context"
	"net/http"
)

// TokenSource supplies a bearer/access token on demand. It is intentionally the
// same minimal shape as golang.org/x/oauth2's token retrieval: a single method
// that returns a fresh, valid token (implementations are responsible for
// caching and refresh).
//
// The core SDK does not know how tokens are minted. Conjur, OAuth, and other
// integrations are provided by opt-in adapter modules (for example the
// auth/conjur sub-module) so that the core module stays dependency-light.
type TokenSource interface {
	// Token returns a currently-valid access token, refreshing if necessary.
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a plain function to the TokenSource interface.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// staticTokenSource always returns the same token.
type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }

// authScheme describes how an access token is placed on the wire.
type authScheme int

const (
	// authNone applies no Authorization header (used for public/unauthenticated endpoints).
	authNone authScheme = iota
	// authConjurToken sets `Authorization: Token token="<token>"`, the scheme
	// the SWA control plane expects for Conjur access tokens.
	authConjurToken
	// authBearer sets `Authorization: Bearer <token>`.
	authBearer
)

// applyAuth writes the Authorization header for the given scheme and token.
func applyAuth(req *http.Request, scheme authScheme, token string) {
	switch scheme {
	case authConjurToken:
		req.Header.Set("Authorization", `Token token="`+token+`"`)
	case authBearer:
		req.Header.Set("Authorization", "Bearer "+token)
	case authNone:
		// no-op
	}
}
