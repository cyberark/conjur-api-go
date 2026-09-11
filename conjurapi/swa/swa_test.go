package swa

import (
	"errors"
	"testing"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

func TestUserMessage_ValidationError(t *testing.T) {
	err := swaerrors.NewValidationError(swaerrors.OpServerGroupsCreate, []swaerrors.FieldViolation{
		{Field: "attestation", Message: "at least one attestation method (x509pop, k8s_psat, gcp_service_account, gemini_enterprise, or aws_iid) must be configured"},
	})

	got := UserMessage(err)
	want := "attestation: at least one attestation method (x509pop, k8s_psat, gcp_service_account, gemini_enterprise, or aws_iid) must be configured"
	if got != want {
		t.Fatalf("UserMessage() = %q, want %q", got, want)
	}
}

func TestUserMessage_APIError(t *testing.T) {
	err := swaerrors.NewAPIError(404, "trust_domain_not_found", "Conjur trust_domain with name 'nonexistent.example.com' not found (status=404, request=GET https://example.com/api/assets/trust_domain/data/swa/trust-domains/nonexistent.example.com): Conjur API error: Trust_domain 'data/swa/trust-domains/nonexistent.example.com' not found in account 'conjur' (conjur_resource_not_found)")

	got := UserMessage(err)
	if got != err.Message {
		t.Fatalf("UserMessage() = %q, want %q", got, err.Message)
	}
}

func TestUserMessage_UnrecognizedError(t *testing.T) {
	err := errors.New("boom")

	got := UserMessage(err)
	if got != "boom" {
		t.Fatalf("UserMessage() = %q, want %q", got, "boom")
	}
}

func TestUserMessage_NilError(t *testing.T) {
	got := UserMessage(nil)
	if got != "" {
		t.Fatalf("UserMessage(nil) = %q, want %q", got, "")
	}
}
