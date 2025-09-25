package conjurapi

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Version should be a number but can also contain dots and dashes (eg. 1.21.0.1-25).
// It can also contain trailing characters (eg. 0.0.dev).
var versionRegex = regexp.MustCompile(`^[\d.-]+`)

func TestServerVersion(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Server version not supported on Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)
			conjur := utils.Client()

			version, err := conjur.ServerVersion()
			require.Error(t, err)
			assert.ErrorContains(t, err, "not supported in Secrets Manager SaaS")
			assert.Empty(t, version)
		})
		return
	}

	t.Run("Gets server version", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)
		conjur := utils.Client()

		version, err := conjur.ServerVersion()
		require.NoError(t, err)

		assert.NotEmpty(t, version)
		assert.Regexp(t, versionRegex, version)
	})

	t.Run("Enterprise (Mocked): Gets server version", func(t *testing.T) {
		mockServer, mockClient := createMockConjurClient(t)
		defer mockServer.Close()
		version, err := mockClient.ServerVersion()
		require.NoError(t, err)

		assert.NotEmpty(t, version)
		assert.Regexp(t, versionRegex, version)
	})

	t.Run("Mocked: Fails to get server version", func(t *testing.T) {
		// Store the original mocked values
		originalMockEnterpriseInfo := mockEnterpriseInfo
		originalMockRootResponse := mockRootResponse

		// Set the mock values
		mockEnterpriseInfo = ""
		mockRootResponse = ""

		// Restore the original mocked values
		defer func() {
			mockEnterpriseInfo = originalMockEnterpriseInfo
			mockRootResponse = originalMockRootResponse
		}()

		mockServer, mockClient := createMockConjurClient(t)
		defer mockServer.Close()
		version, err := mockClient.ServerVersion()
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to retrieve server version")
		assert.Empty(t, version)
	})
}

func TestEnterpriseServerInfo(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Server version not supported on Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)
			conjur := utils.Client()

			info, err := conjur.EnterpriseServerInfo()
			require.Error(t, err)
			assert.ErrorContains(t, err, "not supported in Secrets Manager SaaS")
			assert.Nil(t, info)
		})
		return
	}

	t.Run("Enterprise (Mocked): Gets server info from the '/info' endpoint", func(t *testing.T) {
		mockServer, mockClient := createMockConjurClient(t)
		defer mockServer.Close()
		info, err := mockClient.EnterpriseServerInfo()
		require.NoError(t, err)

		assert.NotEmpty(t, info.Version)
		assert.NotEmpty(t, info.Release)
		assert.NotEmpty(t, info.Role)
		assert.Regexp(t, versionRegex, info.Version)
		assert.Contains(t, info.Services, "ui")
		assert.Contains(t, info.Services, "possum")
		assert.Regexp(t, versionRegex, info.Services["possum"].Version)
	})

	t.Run("OSS: Fails to get server info from the '/info' endpoint", func(t *testing.T) {
		// Use a real Conjur client to test the '/info' endpoint.
		// TODO: Skip this test on Enterprise
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)
		conjur := utils.Client()

		info, err := conjur.EnterpriseServerInfo()
		require.Error(t, err)
		assert.ErrorContains(t, err, "404")
		assert.Nil(t, info)
	})
}

func TestServerVersionFromRoot(t *testing.T) {
	if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Run("Server version not supported on Secrets Manager SaaS", func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			assert.NoError(t, err)
			conjur := utils.Client()

			version, err := conjur.ServerVersionFromRoot()
			require.Error(t, err)
			assert.ErrorContains(t, err, "not supported in Secrets Manager SaaS")
			assert.Empty(t, version)
		})
		// Skip the rest of the tests when running against Secrets Manager SaaS
		return
	}

	t.Run("Gets server version from the root endpoint", func(t *testing.T) {
		utils, err := NewTestUtils(&Config{})
		assert.NoError(t, err)
		conjur := utils.Client()

		version, err := conjur.ServerVersionFromRoot()
		require.NoError(t, err)

		assert.NotEmpty(t, version)
		assert.Regexp(t, versionRegex, version)
	})

	mockedTestCases := []struct {
		name                string
		rootResponse        string
		contentType         string
		expectErrorContains string
	}{
		{
			name:         "HTML Response",
			rootResponse: mockRootResponseHTML,
			contentType:  "text/html",
		},
		{
			name:         "JSON Response",
			rootResponse: mockRootResponseJSON,
			contentType:  "application/json",
		},
		{
			name:                "Empty Response",
			rootResponse:        "",
			contentType:         "application/json",
			expectErrorContains: "failed to parse JSON",
		},
		{
			name:                "Invalid JSON Response",
			rootResponse:        "Invalid response",
			contentType:         "application/json",
			expectErrorContains: "failed to parse JSON",
		},
		{
			name:                "JSON Missing Version Field",
			rootResponse:        `{"not_version": "1.0.0"}`,
			contentType:         "application/json",
			expectErrorContains: "version field not found",
		},
		{
			name:                "Invalid HTML Response",
			rootResponse:        "Invalid response",
			contentType:         "text/html",
			expectErrorContains: "version field not found",
		},
	}

	// Store the original mocked values
	originalMockRootResponse := mockRootResponse
	originalMockRootResponseContentType := mockRootResponseContentType

	t.Cleanup(func() {
		// Restore the original mocked values
		mockRootResponse = originalMockRootResponse
		mockRootResponseContentType = originalMockRootResponseContentType
	})

	for _, tc := range mockedTestCases {
		t.Run("Mocked: "+tc.name, func(t *testing.T) {
			mockRootResponse = tc.rootResponse
			mockRootResponseContentType = tc.contentType
			mockServer, mockClient := createMockConjurClient(t)
			defer mockServer.Close()
			version, err := mockClient.ServerVersionFromRoot()

			if tc.expectErrorContains != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.expectErrorContains)
				assert.Empty(t, version)
				return
			}

			require.NoError(t, err)

			assert.NotEmpty(t, version)
			assert.Regexp(t, versionRegex, version)
		})
	}
}
