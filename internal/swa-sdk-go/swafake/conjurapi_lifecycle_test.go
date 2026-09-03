package swafake_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/swa"
	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake"
)

// These lifecycle tests exercise conjurapi's ClientV2 SWA wiring end-to-end
// against the generated fake server. They live here, in swafake's own
// module, rather than in conjurapi, so that conjurapi's go.mod doesn't pull
// in swafake's echo/oapi-codegen dependencies.

// fakeConjurToken is a syntactically-valid (but not cryptographically real)
// Conjur access token, sufficient to satisfy authn.TokenAuthenticator's
// shape check without a network round-trip to an authenticate endpoint.
const fakeConjurToken = `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

func swaTestClientV2(t *testing.T, fake *swafake.Server) *conjurapi.ClientV2 {
	client, err := conjurapi.NewClientFromToken(conjurapi.Config{
		ApplianceURL: fake.URL(),
		Account:      "account",
		Environment:  conjurapi.EnvironmentSaaS,
	}, fakeConjurToken)
	require.NoError(t, err)
	return client.V2()
}

func TestClientV2_SWA_TrustDomainLifecycle(t *testing.T) {
	fake := swafake.NewTB(t)
	swaClient, err := swaTestClientV2(t, fake).SWA()
	require.NoError(t, err)

	ctx := context.Background()

	created, err := swaClient.TrustDomains().Create(ctx, swa.CreateTrustDomainRequest{Name: "example.org"})
	require.NoError(t, err)
	assert.Equal(t, "example.org", created.Name)

	got, err := swaClient.TrustDomains().Get(ctx, "example.org")
	require.NoError(t, err)
	assert.Equal(t, "example.org", got.Name)

	list, err := swaClient.TrustDomains().List(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, list.TrustDomains, 1)

	updated, err := swaClient.TrustDomains().Update(ctx, "example.org", swa.UpdateTrustDomainRequest{})
	require.NoError(t, err)
	assert.Equal(t, "example.org", updated.Name)

	err = swaClient.TrustDomains().Delete(ctx, "example.org")
	require.NoError(t, err)

	_, err = swaClient.TrustDomains().Get(ctx, "example.org")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestClientV2_SWA_ServerLifecycle(t *testing.T) {
	fake := swafake.NewTB(t,
		swafake.WithTrustDomain("example.org"),
		swafake.WithServerGroup("example.org", swa.CreateServerGroupRequest{Name: "group-a"}),
	)
	swaClient, err := swaTestClientV2(t, fake).SWA()
	require.NoError(t, err)

	ctx := context.Background()

	var authData swa.CreateServerAuthenticationData
	require.NoError(t, authData.FromCreateServerJWTAuthenticationData(swa.CreateServerJWTAuthenticationData{}))

	createResp, err := swaClient.Servers().Create(ctx, "example.org", "group-a", swa.CreateServerRequest{
		Name: "server-a",
		Authentication: swa.CreateServerAuthentication{
			Type: swa.CreateServerAuthenticationType("JWT"),
			Data: authData,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "server-a", createResp.Name)

	got, err := swaClient.Servers().Get(ctx, "example.org", "group-a", createResp.Name)
	require.NoError(t, err)
	assert.Equal(t, createResp.Name, got.Name)

	list, err := swaClient.Servers().List(ctx, "example.org", "group-a", nil)
	require.NoError(t, err)
	assert.Len(t, list.Components, 1)

	err = swaClient.Servers().Delete(ctx, "example.org", "group-a", createResp.Name)
	require.NoError(t, err)

	_, err = swaClient.Servers().Get(ctx, "example.org", "group-a", createResp.Name)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}
