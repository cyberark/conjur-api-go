package swa

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAgentEditor_SetsWhenAbsent(t *testing.T) {
	editor := userAgentEditor("custom-ua")

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, "custom-ua", req.Header.Get("User-Agent"))
}

func TestUserAgentEditor_PreservesExisting(t *testing.T) {
	editor := userAgentEditor("custom-ua")

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "caller-ua")
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, "caller-ua", req.Header.Get("User-Agent"))
}

func TestAcceptEditor_SetsHeader(t *testing.T) {
	editor := acceptEditor("application/json")

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
}

func TestAuthEditor_ConjurToken(t *testing.T) {
	editor := authEditor(authConjurToken, staticTokenSource("tok-123"))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, `Token token="tok-123"`, req.Header.Get("Authorization"))
}

func TestAuthEditor_BearerToken(t *testing.T) {
	editor := authEditor(authBearer, staticTokenSource("tok-123"))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, "Bearer tok-123", req.Header.Get("Authorization"))
}

func TestAuthEditor_PreservesExisting(t *testing.T) {
	editor := authEditor(authBearer, staticTokenSource("tok-123"))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer existing")
	require.NoError(t, editor(context.Background(), req))
	assert.Equal(t, "Bearer existing", req.Header.Get("Authorization"))
}

func TestAuthEditor_TokenSourceError(t *testing.T) {
	errSource := TokenSourceFunc(func(ctx context.Context) (string, error) {
		return "", errors.New("token failed")
	})
	editor := authEditor(authBearer, errSource)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	err = editor(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, "resolving access token: token failed", err.Error())
}

func TestCombineEditors_ChainsAndShortCircuits(t *testing.T) {
	called := 0
	e1 := func(ctx context.Context, req *http.Request) error {
		called++
		req.Header.Set("X-E1", "1")
		return nil
	}
	e2 := func(ctx context.Context, req *http.Request) error {
		called++
		return errors.New("e2 failed")
	}
	e3 := func(ctx context.Context, req *http.Request) error {
		called++
		req.Header.Set("X-E3", "3")
		return nil
	}

	combined := combineEditors(nil, e1, e2, e3)
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	err = combined(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, "e2 failed", err.Error())
	assert.Equal(t, 2, called)
	assert.Equal(t, "1", req.Header.Get("X-E1"))
	assert.Empty(t, req.Header.Get("X-E3"))
}
