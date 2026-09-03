package swa

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

func TestValidateCreateServerGroupRequest(t *testing.T) {
	x509 := &AttestationConfiguration{X509pop: &X509PopConfigurationInput{CaCertificates: "pem"}}

	t.Run("valid with attestation", func(t *testing.T) {
		err := ValidateCreateServerGroupRequest(CreateServerGroupRequest{Name: "sg-1", Attestation: x509})
		require.NoError(t, err)
	})

	t.Run("deprecated node_attestation is not sufficient", func(t *testing.T) {
		// The legacy node_attestation field is no longer supported: a request
		// that only sets it must fail attestation validation.
		err := ValidateCreateServerGroupRequest(CreateServerGroupRequest{
			Name:            "sg-1",
			NodeAttestation: &DeprecatedAttestationConfiguration{X509pop: &X509PopConfigurationInput{CaCertificates: "pem"}},
		})
		require.Error(t, err)
		vErr, ok := swaerrors.AsValidationError(err)
		require.True(t, ok)
		assert.Equal(t, "attestation", vErr.Violations[0].Field)
	})

	t.Run("missing attestation", func(t *testing.T) {
		err := ValidateCreateServerGroupRequest(CreateServerGroupRequest{Name: "sg-1"})
		require.Error(t, err)
		vErr, ok := swaerrors.AsValidationError(err)
		require.True(t, ok)
		require.Len(t, vErr.Violations, 1)
		assert.Equal(t, "attestation", vErr.Violations[0].Field)
	})

	t.Run("invalid name", func(t *testing.T) {
		err := ValidateCreateServerGroupRequest(CreateServerGroupRequest{Name: "bad name!", Attestation: x509})
		require.Error(t, err)
		vErr, ok := swaerrors.AsValidationError(err)
		require.True(t, ok)
		assert.Equal(t, "name", vErr.Violations[0].Field)
	})

	t.Run("too long name", func(t *testing.T) {
		err := ValidateCreateServerGroupRequest(CreateServerGroupRequest{Name: strings.Repeat("a", 61), Attestation: x509})
		require.Error(t, err)
	})
}

func TestValidateNodeGroupCreateRequest(t *testing.T) {
	require.NoError(t, ValidateNodeGroupCreateRequest(NodeGroupCreateRequest{Name: "ng-1", WorkloadType: "unix"}))

	err := ValidateNodeGroupCreateRequest(NodeGroupCreateRequest{Name: "ng-1"})
	require.Error(t, err)
	vErr, ok := swaerrors.AsValidationError(err)
	require.True(t, ok)
	assert.Equal(t, "workload_type", vErr.Violations[0].Field)
}

func TestValidateCreateTrustDomainRequest(t *testing.T) {
	require.NoError(t, ValidateCreateTrustDomainRequest(CreateTrustDomainRequest{Name: "prod.example.com"}))
	require.Error(t, ValidateCreateTrustDomainRequest(CreateTrustDomainRequest{Name: ""}))
}

// Create must reject an invalid request client-side, before any HTTP call.
func TestServerGroups_Create_ValidatesBeforeRequest(t *testing.T) {
	// No routes registered: if Create reached the network, the mock would fail the
	// test. A missing attestation must be rejected client-side first.
	c := newMockAPI(t).Client()

	_, err := c.ServerGroups().Create(context.Background(), "td", CreateServerGroupRequest{Name: "sg"})
	require.Error(t, err)
	_, ok := swaerrors.AsValidationError(err)
	assert.True(t, ok, "expected a *swaerrors.ValidationError")
}
