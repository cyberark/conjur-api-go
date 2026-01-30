package conjurapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var batchSecretsTestPolicy = `
- !host bob
- &test-variables
  - !variable secret1
  - !variable secret2
  - !variable secret3
- !permit
  role: !host bob
  privileges: [ read, execute ]
  resources: *test-variables
`

func TestClientV2_BatchRetrieveSecrets(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	_, err = utils.Setup(batchSecretsTestPolicy)
	require.NoError(t, err)
	conjur := utils.Client().V2()

	err = utils.Client().AddSecret(utils.IDWithPath("secret1"), "value1")
	require.NoError(t, err)
	err = utils.Client().AddSecret(utils.IDWithPath("secret2"), "value2")
	require.NoError(t, err)
	err = utils.Client().AddSecret(utils.IDWithPath("secret3"), "value3")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		identifiers    []string
		expectError    string
		expectedCount  int
		expectedStatus map[int]int
	}{
		{
			name:          "Retrieve single secret",
			identifiers:   []string{utils.IDWithPath("secret1")},
			expectedCount: 1,
			expectedStatus: map[int]int{
				200: 1,
			},
		},
		{
			name:          "Retrieve multiple secrets",
			identifiers:   []string{utils.IDWithPath("secret1"), utils.IDWithPath("secret2"), utils.IDWithPath("secret3")},
			expectedCount: 3,
			expectedStatus: map[int]int{
				200: 3,
			},
		},
		{
			name:          "Retrieve mix of existing and non-existing secrets",
			identifiers:   []string{utils.IDWithPath("secret1"), utils.IDWithPath("secret2"), utils.IDWithPath("secret3"), utils.IDWithPath("nonexistent1"), utils.IDWithPath("nonexistent2")},
			expectedCount: 5,
			expectedStatus: map[int]int{
				200: 3,
				404: 2,
			},
		},
		{
			name:        "Empty identifiers list",
			identifiers: []string{},
			expectError: "Must specify at least one secret identifier",
		},
		{
			name:        "Empty identifier",
			identifiers: []string{""},
			expectError: "Must specify at least one secret identifier",
		},
		{
			name:          "Mixed empty and non-empty identifiers",
			identifiers:   []string{utils.IDWithPath("secret1"), "", utils.IDWithPath("secret2"), ""},
			expectedCount: 2,
			expectedStatus: map[int]int{
				200: 2,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := conjur.BatchRetrieveSecrets(tc.identifiers)
			if tc.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, tc.expectedCount, len(response.Secrets))

			statusCounts := make(map[int]int)
			for _, secret := range response.Secrets {
				statusCounts[secret.Status]++
				assert.NotEmpty(t, secret.ID)
				// Only secrets with 200 status should have non-empty values
				if secret.Status == 200 {
					assert.NotEmpty(t, secret.Value)
				}
			}
			assert.Equal(t, tc.expectedStatus, statusCounts, "Status code should match expected")
		})
	}
}

func TestClientV2_BatchRetrieveSecretsRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		identifiers   []string
		expectError   string
		expectedCount int // expected count after filtering empty identifiers
	}{
		{
			name:          "Valid single identifier",
			identifiers:   []string{"data/test/secret1"},
			expectError:   "",
			expectedCount: 1,
		},
		{
			name:          "Valid multiple identifiers",
			identifiers:   []string{"data/test/secret1", "data/test/secret2", "data/test/secret3"},
			expectError:   "",
			expectedCount: 3,
		},
		{
			name:        "Empty identifiers list",
			identifiers: []string{},
			expectError: "Must specify at least one secret identifier",
		},
		{
			name:        "Empty string identifier",
			identifiers: []string{""},
			expectError: "Must specify at least one secret identifier",
		},
		{
			name:          "Mixed empty and non-empty identifiers",
			identifiers:   []string{"data/test/secret1", "", "data/test/secret2"},
			expectError:   "",
			expectedCount: 2,
		},
		{
			name:        "Too many identifiers",
			identifiers: make([]string, 251),
			expectError: "Cannot request more than 250 secrets at once",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize identifiers for the "too many" test case
			if len(tc.identifiers) == 251 {
				for i := 0; i < 251; i++ {
					tc.identifiers[i] = fmt.Sprintf("data/test/secret%d", i)
				}
			}

			req, err := client.V2().BatchRetrieveSecretsRequest(tc.identifiers)
			if tc.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, req)
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "localhost/secrets/account/values", req.URL.Path)
			assert.Equal(t, http.MethodPost, req.Method)

			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			var batchReq BatchSecretRequest
			err = json.Unmarshal(body, &batchReq)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCount, len(batchReq.IDs))
		})
	}
}

func TestClientV2_ValidateSecretIdentifiers(t *testing.T) {
	testCases := []struct {
		name            string
		identifiers     []string
		expectError     bool
		errorMsg        string
		expectedIDCount int
	}{
		{
			name:            "Valid identifiers",
			identifiers:     []string{"secret1", "secret2"},
			expectError:     false,
			expectedIDCount: 2,
		},
		{
			name:            "Valid identifiers with empty strings filtered out",
			identifiers:     []string{"secret1", ""},
			expectError:     false,
			expectedIDCount: 1,
		},
		{
			name:        "All empty identifiers",
			identifiers: []string{"", ""},
			expectError: true,
			errorMsg:    "Must specify at least one secret identifier",
		},
		{
			name:        "Too many identifiers",
			identifiers: make([]string, 251),
			expectError: true,
			errorMsg:    "Cannot request more than 250 secrets at once",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.identifiers) == 251 {
				for i := 0; i < 251; i++ {
					tc.identifiers[i] = fmt.Sprintf("secret%d", i)
				}
			}

			validIDs, err := ValidateSecretIdentifiers(tc.identifiers)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				assert.Nil(t, validIDs)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validIDs)
				assert.Equal(t, tc.expectedIDCount, len(validIDs))
				for _, id := range validIDs {
					assert.NotEmpty(t, id)
				}
			}
		})
	}
}
