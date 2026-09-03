package swa

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerGroups_Apply_CreatesWhenAbsent(t *testing.T) {
	api := newMockAPI(t)
	get := api.GET("*").RespondJSON(http.StatusNotFound, map[string]any{"code": "server_group_not_found", "message": "nope"})
	post := api.POST("*").RespondJSON(http.StatusCreated, map[string]any{"name": "sg", "trust_domain_name": "td"})
	c := api.Client()

	sg, action, err := c.ServerGroups().Apply(context.Background(), "td", CreateServerGroupRequest{
		Name:        "sg",
		Attestation: &AttestationConfiguration{X509pop: &X509PopConfigurationInput{CaCertificates: "pem"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []*route{get, post}, api.Requests(), "Apply must probe with GET before creating")
	assert.Equal(t, ApplyActionCreated, action)
	assert.Equal(t, "sg", sg.Name)
}

func TestServerGroups_Apply_UpdatesWhenPresent(t *testing.T) {
	api := newMockAPI(t)
	get := api.GET("*").RespondJSON(http.StatusOK, map[string]any{"name": "sg", "trust_domain_name": "td"})
	patch := api.PATCH("*").RespondJSON(http.StatusOK, map[string]any{"name": "sg", "trust_domain_name": "td"})
	c := api.Client()

	sg, action, err := c.ServerGroups().Apply(context.Background(), "td", CreateServerGroupRequest{
		Name:        "sg",
		Attestation: &AttestationConfiguration{X509pop: &X509PopConfigurationInput{CaCertificates: "pem"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []*route{get, patch}, api.Requests(), "Apply must probe with GET before updating")
	assert.Equal(t, ApplyActionUpdated, action)
	assert.Equal(t, "sg", sg.Name)
}

// When Apply updates an existing node group and the desired spec omits the
// workload configuration, it must send a present-but-empty configuration to reset
// it to defaults (the SDK's documented write semantics).
func TestNodeGroups_Apply_ResetsWorkloadConfigOnUpdate(t *testing.T) {
	api := newMockAPI(t)
	get := api.GET("*").RespondJSON(http.StatusOK, map[string]any{"name": "ng"})
	patch := api.PATCH("*").RespondJSON(http.StatusOK, map[string]any{"name": "ng"})
	c := api.Client()

	_, action, err := c.NodeGroups().Apply(context.Background(), "td", "sg", NodeGroupCreateRequest{
		Name:         "ng",
		WorkloadType: "unix",
		// WorkloadConfiguration deliberately omitted.
	})
	require.NoError(t, err)
	assert.Equal(t, []*route{get, patch}, api.Requests(), "Apply must probe with GET before updating")
	assert.Equal(t, ApplyActionUpdated, action)

	var patchBody map[string]any
	patch.LastRequest().DecodeBody(t, &patchBody)
	wc, ok := patchBody["workload_configuration"]
	require.True(t, ok, "workload_configuration must be present to signal reset")
	assert.Empty(t, wc, "reset is signalled by a present-but-empty object")
}

func TestToUpdateTrustDomainRequest_MapsJWTAndX509(t *testing.T) {
	alg := SignatureAlgorithmES256
	kt := SigningKeyTypeECP256
	ttl := int32(600)
	x509ttl := int32(3600)

	out := toUpdateTrustDomainRequest(CreateTrustDomainRequest{
		Name: "prod.example.com",
		Jwt: &JWTConfigurationInput{
			SignatureAlgorithm: &alg,
			SigningKeyType:     &kt,
			SigningKeyTtl:      &ttl,
			TokenTtl:           &ttl,
		},
		X509: &X509ConfigurationInput{WorkloadTtl: &x509ttl},
	})

	require.NotNil(t, out.Jwt)
	require.NotNil(t, out.Jwt.SignatureAlgorithm)
	assert.Equal(t, string(alg), string(*out.Jwt.SignatureAlgorithm))
	require.NotNil(t, out.Jwt.SigningKeyType)
	assert.Equal(t, string(kt), string(*out.Jwt.SigningKeyType))
	assert.Equal(t, ttl, *out.Jwt.SigningKeyTtl)
	require.NotNil(t, out.X509)
	assert.Equal(t, x509ttl, out.X509.WorkloadTtl)
}

func TestToUpdateNodeGroupRequest_NilWorkloadConfigResets(t *testing.T) {
	out := toUpdateNodeGroupRequest(NodeGroupCreateRequest{Name: "ng", WorkloadType: "unix"})
	require.NotNil(t, out.WorkloadConfiguration)
	assert.Nil(t, out.WorkloadConfiguration.SpiffeIdTemplate)
	assert.Nil(t, out.WorkloadConfiguration.WorkloadRegistrationPolicies)
}

// jwtCreateReq builds a minimal valid server create request with a JWT authenticator.
func jwtCreateReq(t *testing.T, name string) CreateServerRequest {
	t.Helper()
	req := CreateServerRequest{
		Name:           name,
		Authentication: CreateServerAuthentication{Type: "JWT"},
	}
	issuer := "https://issuer.example.com"
	require.NoError(t, req.Authentication.Data.FromCreateServerJWTAuthenticationData(CreateServerJWTAuthenticationData{
		Sub:    "workload-subject",
		Issuer: &issuer,
	}))
	return req
}

func TestServers_Apply_CreatesAndReturnsAuthnID(t *testing.T) {
	api := newMockAPI(t)
	get := api.GET("*").RespondJSON(http.StatusNotFound, map[string]any{"code": "server_not_found", "message": "nope"})
	post := api.POST("*").RespondJSON(http.StatusCreated, map[string]any{"name": "srv", "authn_id": "authn-abc"})
	c := api.Client()

	srv, action, err := c.Servers().Apply(context.Background(), "td", "sg", jwtCreateReq(t, "srv"))
	require.NoError(t, err)
	assert.Equal(t, []*route{get, post}, api.Requests(), "Apply must probe with GET before creating")
	assert.Equal(t, ApplyActionCreated, action)
	assert.Equal(t, "srv", srv.Name)
	require.NotNil(t, srv.AuthnId)
	assert.Equal(t, "authn-abc", *srv.AuthnId)
}

// On update, the server subject must be dropped (immutable) while other auth
// fields carry over.
func TestServers_Apply_UpdateDropsSubject(t *testing.T) {
	api := newMockAPI(t)
	get := api.GET("*").RespondJSON(http.StatusOK, map[string]any{"name": "srv"})
	patch := api.PATCH("*").RespondJSON(http.StatusOK, map[string]any{"name": "srv"})
	c := api.Client()

	_, action, err := c.Servers().Apply(context.Background(), "td", "sg", jwtCreateReq(t, "srv"))
	require.NoError(t, err)
	assert.Equal(t, []*route{get, patch}, api.Requests(), "Apply must probe with GET before updating")
	assert.Equal(t, ApplyActionUpdated, action)

	var patchBody map[string]any
	patch.LastRequest().DecodeBody(t, &patchBody)
	auth, ok := patchBody["authentication"].(map[string]any)
	require.True(t, ok)
	data, ok := auth["data"].(map[string]any)
	require.True(t, ok)
	_, hasSub := data["sub"]
	assert.False(t, hasSub, "subject must not be sent on update (immutable)")
	assert.Equal(t, "https://issuer.example.com", data["issuer"], "other auth fields carry over")
}
