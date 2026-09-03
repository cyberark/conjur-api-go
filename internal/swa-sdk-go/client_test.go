package swa

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

func TestNewClient_RequiresBaseURL(t *testing.T) {
	_, err := NewClient(WithConjurToken("x"))
	require.ErrorIs(t, err, ErrMissingBaseURL)
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://h.example.com":      "https://h.example.com",
		"https://h.example.com/":     "https://h.example.com",
		"https://h.example.com/api":  "https://h.example.com",
		"https://h.example.com/api/": "https://h.example.com",
	}
	for in, want := range cases {
		assert.Equalf(t, want, normalizeBaseURL(in), "normalizeBaseURL(%q)", in)
	}
}

func TestTrustDomains_Get_SetsAuthAndHeaders(t *testing.T) {
	api := newMockAPI(t)
	route := api.GET("/api/swa/trust-domains/prod.example.com").
		RespondJSON(http.StatusOK, map[string]any{"name": "prod.example.com"})
	c := api.Client()

	td, err := c.TrustDomains().Get(context.Background(), "prod.example.com")
	require.NoError(t, err)
	require.NotNil(t, td)
	assert.Equal(t, "prod.example.com", td.Name)

	req := route.LastRequest()
	require.NotNil(t, req)
	assert.Equal(t, `Token token="test-token"`, req.Header.Get("Authorization"))
	assert.Equal(t, DefaultMediaType, req.Header.Get("Accept"))
	assert.Contains(t, req.Header.Get("User-Agent"), "swa-sdk-go/")
}

func TestTrustDomains_Get_NotFound(t *testing.T) {
	api := newMockAPI(t)
	api.GET("/api/swa/trust-domains/x").RespondJSON(http.StatusNotFound,
		map[string]any{"code": "trust_domain_not_found", "message": "trust domain 'x' not found"},
		withHeader("X-Request-Id", "req-123"),
	)
	c := api.Client()

	_, err := c.TrustDomains().Get(context.Background(), "x")
	require.Error(t, err)
	assert.True(t, swaerrors.IsNotFound(err))

	apiErr, ok := swaerrors.AsAPIError(err)
	require.True(t, ok)
	assert.Equal(t, swaerrors.OpTrustDomainsGet, apiErr.Op)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Equal(t, "trust_domain_not_found", apiErr.Code)
	assert.Equal(t, "req-123", apiErr.RequestID)
}

func TestTrustDomains_Create(t *testing.T) {
	api := newMockAPI(t)
	route := api.POST("/api/swa/trust-domains").
		RespondJSON(http.StatusCreated, map[string]any{"name": "new.example.com"})
	c := api.Client()

	td, err := c.TrustDomains().Create(context.Background(), CreateTrustDomainRequest{Name: "new.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "new.example.com", td.Name)

	var body map[string]any
	route.LastRequest().DecodeBody(t, &body)
	assert.Equal(t, "new.example.com", body["name"])
}

func TestTrustDomains_Delete_NoContent(t *testing.T) {
	api := newMockAPI(t)
	// First delete succeeds (204); a second delete of the now-gone resource
	// returns 422, which the SDK surfaces as a validation API error.
	api.DELETE("/api/swa/trust-domains/x").
		RespondStatus(http.StatusNoContent).
		RespondJSON(http.StatusUnprocessableEntity, map[string]string{
			"code":    "trust_domain_not_deletable",
			"message": "trust domain does not exist",
		})
	c := api.Client()

	require.NoError(t, c.TrustDomains().Delete(context.Background(), "x"))

	err := c.TrustDomains().Delete(context.Background(), "x")
	require.Error(t, err)
	assert.True(t, swaerrors.IsValidation(err), "expected a 422 validation error, got %v", err)
	apiErr, ok := swaerrors.AsAPIError(err)
	require.True(t, ok)
	assert.Equal(t, "trust_domain_not_deletable", apiErr.Code)
}

func TestTrustDomains_All_Paginates(t *testing.T) {
	// Page 1 (offset 0) returns 2 items; page 2 (offset 2) returns 1 (short -> end).
	// Queued responses are returned in order, so a single route models both pages.
	api := newMockAPI(t)
	api.GET("/api/swa/trust-domains").
		RespondJSON(http.StatusOK, map[string]any{
			"trust_domains": []map[string]any{{"name": "a"}, {"name": "b"}},
			"count":         2,
		}).
		RespondJSON(http.StatusOK, map[string]any{
			"trust_domains": []map[string]any{{"name": "c"}},
			"count":         1,
		})
	c := api.Client()

	var names []string
	for td, err := range c.TrustDomains().All(context.Background(), &ListOptions{Limit: 2}) {
		require.NoError(t, err)
		names = append(names, td.Name)
	}
	assert.Equal(t, []string{"a", "b", "c"}, names)
}

func TestServers_List_UsesComponentsField(t *testing.T) {
	api := newMockAPI(t)
	api.GET("/api/swa/trust-domains/td/server-groups/sg/components").
		RespondJSON(http.StatusOK, map[string]any{
			"components": []map[string]any{{"name": "srv-1"}},
			"count":      1,
		})
	c := api.Client()

	list, err := c.Servers().List(context.Background(), "td", "sg", nil)
	require.NoError(t, err)
	require.Len(t, list.Components, 1)
	assert.Equal(t, "srv-1", list.Components[0].Name)
}

func TestRetry_IdempotentRecoversFrom503(t *testing.T) {
	api := newMockAPI(t)
	route := api.GET("/api/swa/trust-domains/prod").
		RespondStatus(http.StatusServiceUnavailable).
		RespondStatus(http.StatusServiceUnavailable).
		RespondStatus(http.StatusServiceUnavailable).
		RespondJSON(http.StatusOK, map[string]any{"name": "prod"})
	c := api.Client(WithRetry(RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}))

	td, err := c.TrustDomains().Get(context.Background(), "prod")
	require.NoError(t, err)
	assert.Equal(t, "prod", td.Name)

	// MaxRetries: 3 allows 1 initial attempt + 3 retries = 4 attempts total;
	// this exhausts all 3 retries before recovering on the final one.
	reqs := route.Requests()
	require.Len(t, reqs, 4)
	assert.Equal(t, http.StatusServiceUnavailable, reqs[0].Response.status, "1st attempt hit the 503")
	assert.Equal(t, http.StatusServiceUnavailable, reqs[1].Response.status, "2nd attempt hit the 503")
	assert.Equal(t, http.StatusServiceUnavailable, reqs[2].Response.status, "3rd attempt hit the 503")
	assert.Equal(t, http.StatusOK, reqs[3].Response.status, "4th attempt recovered")
}

func TestRetry_NotAppliedToCreate(t *testing.T) {
	api := newMockAPI(t)
	route := api.POST("/api/swa/trust-domains").RespondStatus(http.StatusServiceUnavailable)
	c := api.Client(WithRetry(RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond}))

	_, err := c.TrustDomains().Create(context.Background(), CreateTrustDomainRequest{Name: "z"})
	require.Error(t, err)
	assert.True(t, swaerrors.IsServerError(err))
	assert.Equal(t, 1, route.Count(), "POST create must not be retried")
}

func TestWellKnown_CABundles_Format(t *testing.T) {
	api := newMockAPI(t)
	route := api.GET("*").RespondJSON(http.StatusOK, map[string]any{"bundle": "-----BEGIN CERTIFICATE-----"})
	c := api.Client()

	bundle, err := c.WellKnown().CABundles(context.Background(), "td", CABundleFormatPEM)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Equal(t, "pem", route.LastRequest().Query.Get("format"))
}

func TestLivez(t *testing.T) {
	api := newMockAPI(t)
	api.GET("/api/swa/livez").RespondJSON(http.StatusOK, map[string]any{"status": "ok"})
	c := api.Client()

	require.NoError(t, c.Livez(context.Background()))
}

func TestAPIError_Error(t *testing.T) {
	err := &swaerrors.APIError{Op: swaerrors.OpTrustDomainsGet, StatusCode: 404, Code: "trust_domain_not_found", Message: "not found", RequestID: "r1"}
	assert.Equal(t, fmt.Sprintf("swa: TrustDomains.Get: not found (trust_domain_not_found) [status=404 request_id=r1]"), err.Error())
}

func TestNewClient_DoesNotMutateCallerHTTPClient(t *testing.T) {
	origTransport := &http.Transport{}
	customClient := &http.Client{Transport: origTransport}

	dummyTransport := &http.Transport{}
	c, err := NewClient(
		WithBaseURL("https://example.com"),
		WithHTTPClient(customClient),
		WithRoundTripper(dummyTransport),
	)
	require.NoError(t, err)
	require.NotNil(t, c)

	assert.Same(t, origTransport, customClient.Transport)
}
