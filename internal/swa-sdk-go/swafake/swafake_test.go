package swafake_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	swa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake"
)

func TestFake_TrustDomainApply_CreateThenUpdate(t *testing.T) {
	fake := swafake.NewTB(t)
	c := fake.Client()
	ctx := context.Background()

	td, action, err := c.TrustDomains().Apply(ctx, swa.CreateTrustDomainRequest{Name: "prod.example.com"})
	require.NoError(t, err)
	assert.Equal(t, swa.ApplyActionCreated, action)
	assert.Equal(t, "prod.example.com", td.Name)
	// Server-side defaults are applied by the fake, just like the real service.
	assert.NotEmpty(t, td.Jwt.DiscoveryEndpoints.JwksUri)
	assert.Equal(t, int32(3600), td.X509.WorkloadTtl)

	// A second Apply reconciles to the update path.
	_, action, err = c.TrustDomains().Apply(ctx, swa.CreateTrustDomainRequest{Name: "prod.example.com"})
	require.NoError(t, err)
	assert.Equal(t, swa.ApplyActionUpdated, action)
}

func TestFake_GetMissing_IsNotFound(t *testing.T) {
	fake := swafake.NewTB(t)
	c := fake.Client()

	_, err := c.TrustDomains().Get(context.Background(), "missing.example.com")
	require.Error(t, err)
	assert.True(t, swaerrors.IsNotFound(err), "expected a not-found error, got %v", err)
}

func TestFake_SeededServerGroup_GCPDefaultAudience(t *testing.T) {
	aud := "prod.example.com"
	fake := swafake.NewTB(t,
		swafake.WithTrustDomain(aud),
		swafake.WithServerGroup(aud, swa.CreateServerGroupRequest{
			Name: "web",
			Attestation: &swa.AttestationConfiguration{
				GcpServiceAccount: &swa.GcpServiceAccountAttestationConfiguration{
					AllowedProjectIds: []string{"proj-1"},
				},
			},
		}),
	)
	c := fake.Client()

	sg, err := c.ServerGroups().Get(context.Background(), aud, "web")
	require.NoError(t, err)
	require.NotNil(t, sg.Attestation)
	require.NotNil(t, sg.Attestation.GcpServiceAccount)
	require.NotNil(t, sg.Attestation.GcpServiceAccount.Audiences)
	assert.Equal(t, []string{swafake.DefaultGCPAttestationAudience}, *sg.Attestation.GcpServiceAccount.Audiences)
}

func TestFake_SeededServerGroup_ImplicitTrustDomain(t *testing.T) {
	tdName := "implicit.example.com"
	fake := swafake.NewTB(t,
		swafake.WithServerGroup(tdName, swa.CreateServerGroupRequest{
			Name: "worker",
		}),
	)
	c := fake.Client()

	td, err := c.TrustDomains().Get(context.Background(), tdName)
	require.NoError(t, err)
	assert.Equal(t, tdName, td.Name)

	sg, err := c.ServerGroups().Get(context.Background(), tdName, "worker")
	require.NoError(t, err)
	assert.Equal(t, "worker", sg.Name)
}

func TestFake_SeededServerGroup_AwsIidAttestor(t *testing.T) {
	tdName := "prod.example.com"
	sgName := "aws-workers"
	mgmtAccountID := "123456789012"
	fake := swafake.NewTB(t,
		swafake.WithAwsIidAttestor(
			tdName,
			sgName,
			"my-role",
			swa.AwsIidAttestationConfigurationPartitionAws,
			&swa.AwsIidVerifyOrganizationConfiguration{
				ManagementAccountId: &mgmtAccountID,
			},
		),
	)
	c := fake.Client()

	sg, err := c.ServerGroups().Get(context.Background(), tdName, sgName)
	require.NoError(t, err)
	require.NotNil(t, sg.Attestation)
	require.NotNil(t, sg.Attestation.AwsIid)
	assert.Equal(t, "my-role", *sg.Attestation.AwsIid.AssumeRole)
	assert.Equal(t, swa.AwsIidAttestationConfigurationPartitionAws, *sg.Attestation.AwsIid.Partition)
	require.NotNil(t, sg.Attestation.AwsIid.VerifyOrganization)
	assert.Equal(t, mgmtAccountID, *sg.Attestation.AwsIid.VerifyOrganization.ManagementAccountId)
}

func TestFake_FaultInjection(t *testing.T) {
	fake := swafake.NewTB(t,
		swafake.WithError(http.MethodGet, "/trust-domains/", http.StatusServiceUnavailable, "unavailable", "try later"),
	)
	c := fake.Client(swa.WithRetry(swa.RetryPolicy{}))

	_, err := c.TrustDomains().Get(context.Background(), "prod.example.com")
	require.Error(t, err)
	assert.True(t, swaerrors.IsServerError(err), "expected a 5xx error, got %v", err)
}

func TestFake_RequestCapture(t *testing.T) {
	fake := swafake.NewTB(t)
	c := fake.Client()

	_, err := c.TrustDomains().Create(context.Background(), swa.CreateTrustDomainRequest{Name: "prod.example.com"})
	require.NoError(t, err)

	reqs := fake.Requests()
	require.NotEmpty(t, reqs)
	last := reqs[len(reqs)-1]
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/api/swa/trust-domains", last.Path)
	assert.Contains(t, last.Header.Get("Authorization"), "swafake-token")

	var body swa.CreateTrustDomainRequest
	require.NoError(t, last.DecodeBody(&body))
	assert.Equal(t, "prod.example.com", body.Name)
}

func TestFake_MissingAuth_IsUnauthorized(t *testing.T) {
	fake := swafake.NewTB(t)
	// A raw client with no token: the fake should reject it.
	c, err := swa.NewClient(swa.WithBaseURL(fake.URL()))
	require.NoError(t, err)

	_, err = c.TrustDomains().Get(context.Background(), "prod.example.com")
	require.Error(t, err)
	assert.True(t, swaerrors.IsUnauthorized(err), "expected unauthorized, got %v", err)
}

// Fake satisfies the swafake.Fake interface.
var _ swafake.Fake = (*swafake.Server)(nil)
