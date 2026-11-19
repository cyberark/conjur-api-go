package contract

import (
	"os"
	"testing"
)

// TestMain is the package's one place for test-binary setup.
func TestMain(m *testing.M) {
	enableUnreleasedCapabilitiesForTests()
	os.Exit(m.Run())
}

// enableUnreleasedCapabilitiesForTests lets the platform and version tests see
// the capabilities as they will be once released. TestUnreleased clears it to
// test the refusal.
func enableUnreleasedCapabilitiesForTests() {
	os.Setenv(UnreleasedOverrideEnvVar, "true")
}
