package conjurapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/conjur-api-go/conjurapi/swa"
)

// TestClientV2_SwaLifecycle exercises the full SWA resource chain (trust
// domain -> server group -> node group -> server) plus the well-known
// discovery endpoints against a real Conjur instance, through ClientV2.SWA(),
// following the same NewTestUtils(&Config{}) convention used by the other
// cloud-only v2 features (secret_static_v2_test.go, issuer_v2_test.go). On
// self-hosted Conjur it only asserts the cloud-only rejection; on Conjur
// Cloud it runs the full create/read/delete lifecycle.
func TestClientV2_SwaLifecycle(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)

	conjur := utils.Client().V2()

	if !conjur.config.IsSaaS() {
		_, err := conjur.SWA()
		require.Error(t, err)
		require.Contains(t, err.Error(), "is not supported in Idira Secrets Manager/Conjur OSS")
		return
	}

	swaClient, err := conjur.SWA()
	require.NoError(t, err)

	ctx := context.Background()

	trustDomainName := "e2e-test.example.com"
	serverGroupName := "e2e-test-servers"
	nodeGroupName := "e2e-test-nodes"
	serverName := "e2e-test-server"

	signingKeyType := swa.SigningKeyTypeECP256
	signatureAlgorithm := swa.SignatureAlgorithmES256
	td, err := swaClient.TrustDomains().Create(ctx, swa.CreateTrustDomainRequest{
		Name: trustDomainName,
		Jwt: &swa.JWTConfigurationInput{
			SigningKeyType:     &signingKeyType,
			SignatureAlgorithm: &signatureAlgorithm,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, trustDomainName, td.Name)

	readTD, err := swaClient.TrustDomains().Get(ctx, trustDomainName)
	require.NoError(t, err)
	assert.Equal(t, trustDomainName, readTD.Name)

	description := "e2e test server group"
	sg, err := swaClient.ServerGroups().Create(ctx, trustDomainName, swa.CreateServerGroupRequest{
		Name:        serverGroupName,
		Description: &description,
		Attestation: &swa.AttestationConfiguration{
			X509pop: &swa.X509PopConfigurationInput{CaCertificates: "pem"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, serverGroupName, sg.Name)

	readSG, err := swaClient.ServerGroups().Get(ctx, trustDomainName, serverGroupName)
	require.NoError(t, err)
	assert.Equal(t, serverGroupName, readSG.Name)

	nodeGroupDescription := "e2e test node group"
	ng, err := swaClient.NodeGroups().Create(ctx, trustDomainName, serverGroupName, swa.NodeGroupCreateRequest{
		Name:         nodeGroupName,
		WorkloadType: swa.WorkloadType("unix"),
		Description:  &nodeGroupDescription,
	})
	require.NoError(t, err)
	assert.Equal(t, nodeGroupName, ng.Name)

	readNG, err := swaClient.NodeGroups().Get(ctx, trustDomainName, serverGroupName, nodeGroupName)
	require.NoError(t, err)
	assert.Equal(t, nodeGroupName, readNG.Name)

	jwksURI := "https://example.com/.well-known/jwks"
	var authData swa.CreateServerAuthenticationData
	require.NoError(t, authData.FromCreateServerJWTAuthenticationData(swa.CreateServerJWTAuthenticationData{
		Sub:     "e2e-test-app",
		JwksUri: &jwksURI,
	}))

	srv, err := swaClient.Servers().Create(ctx, trustDomainName, serverGroupName, swa.CreateServerRequest{
		Name: serverName,
		Authentication: swa.CreateServerAuthentication{
			Type: swa.CreateServerAuthenticationType("JWT"),
			Data: authData,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, serverName, srv.Name)
	assert.NotEmpty(t, srv.AuthnId)

	readSrv, err := swaClient.Servers().Get(ctx, trustDomainName, serverGroupName, serverName)
	require.NoError(t, err)
	assert.Equal(t, serverName, readSrv.Name)

	oidc, err := swaClient.WellKnown().OpenIDConfiguration(ctx, trustDomainName)
	require.NoError(t, err)
	assert.NotEmpty(t, oidc.Issuer)

	// jwks.Keys is expected to be empty here: signing keys are only
	// populated once an external server component pushes its public key via
	// the customer-components signing-keys API, which this SDK does not
	// call as part of trust domain creation.
	_, err = swaClient.WellKnown().JWKS(ctx, trustDomainName)
	require.NoError(t, err)

	err = swaClient.Servers().Delete(ctx, trustDomainName, serverGroupName, serverName)
	assert.NoError(t, err)

	err = swaClient.NodeGroups().Delete(ctx, trustDomainName, serverGroupName, nodeGroupName)
	assert.NoError(t, err)

	err = swaClient.ServerGroups().Delete(ctx, trustDomainName, serverGroupName)
	assert.NoError(t, err)

	err = swaClient.TrustDomains().Delete(ctx, trustDomainName)
	assert.NoError(t, err)
}
