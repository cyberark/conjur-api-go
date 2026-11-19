package conjurapi

import (
	"os"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
)

// TestMain is the package's one place for test-binary setup.
func TestMain(m *testing.M) {
	resetDefaultCredentialStorageModeForTests()
	enableUnreleasedCapabilitiesForTests()
	os.Exit(m.Run())
}

// enableUnreleasedCapabilitiesForTests lets the whole test binary, e2e tests
// included, call the V2 APIs the SDK refuses until they're released.
// TestSubmitRequest_UnreleasedV2 clears it to test the refusal.
func enableUnreleasedCapabilitiesForTests() {
	os.Setenv(contract.UnreleasedOverrideEnvVar, "true")
}
