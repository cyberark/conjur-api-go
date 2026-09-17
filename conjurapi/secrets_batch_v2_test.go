package conjurapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	if !conjur.config.IsSaaS() {
		t.Skip("Skipping V2 Batch Retrieve Secrets test for on-prem")
	}

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

func TestClientV2_BatchRetrieveSecrets_EnvironmentGuard(t *testing.T) {
	// The V2 batch guard must key off the configured Environment, not the
	// hostname, so Edge (arbitrary hostnames behind '/api') is supported.
	tests := []struct {
		name          string
		environment   EnvironmentType
		appliance     string
		expectBlocked bool
	}{
		{
			name:          "Self-hosted is blocked",
			environment:   EnvironmentSH,
			appliance:     "https://conjur.example.com",
			expectBlocked: true,
		},
		{
			name:          "OSS is blocked",
			environment:   EnvironmentOSS,
			appliance:     "https://conjur.example.com",
			expectBlocked: true,
		},
		{
			name:          "SaaS on arbitrary Edge hostname is allowed past the guard",
			environment:   EnvironmentSaaS,
			appliance:     "https://edge.customer.example.com/api",
			expectBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClientV2{Client: &Client{config: Config{
				Environment:  tt.environment,
				ApplianceURL: tt.appliance,
				Account:      "myacct",
			}}}

			_, err := c.BatchRetrieveSecrets([]string{"data/test/secret1"})
			require.Error(t, err)
			if tt.expectBlocked {
				assert.Contains(t, err.Error(), fmt.Sprintf(NotSupportedInConjurEnterprise, "V2 Batch Retrieve Secrets API"))
			} else {
				// Past the guard, the call fails for an unrelated reason (no live
				// server/token), but must not be blocked as unsupported.
				assert.NotContains(t, err.Error(), fmt.Sprintf(NotSupportedInConjurEnterprise, "V2 Batch Retrieve Secrets API"))
			}
		})
	}
}

func TestClientV2_batchSecretsURL(t *testing.T) {
	tests := []struct {
		name        string
		environment EnvironmentType
		appliance   string
		account     string
		expected    string
	}{
		{
			name:        "SaaS omits the account",
			environment: EnvironmentSaaS,
			appliance:   "https://tenant.secretsmgr.cyberark.cloud",
			account:     "conjur",
			expected:    "https://tenant.secretsmgr.cyberark.cloud/api/secrets/values",
		},
		{
			name:        "Edge (saas via /api) omits the account",
			environment: EnvironmentSaaS,
			appliance:   "https://edge.customer.example.com/api",
			account:     "myacct",
			expected:    "https://edge.customer.example.com/api/secrets/values",
		},
		{
			name:        "Self-hosted keeps the account",
			environment: EnvironmentSH,
			appliance:   "https://conjur.example.com",
			account:     "myacct",
			expected:    "https://conjur.example.com/secrets/myacct/values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ClientV2{Client: &Client{config: Config{
				Environment:  tt.environment,
				ApplianceURL: tt.appliance,
				Account:      tt.account,
			}}}
			assert.Equal(t, tt.expected, c.batchSecretsURL())
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

// --- partial-failure surfacing and per-secret detail ---

func newSaaSBatchServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
	})
	mux.HandleFunc("/", handler)

	ts := httptest.NewServer(mux)
	client, err := NewClientFromJwt(Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSaaS,
	})
	if err != nil {
		ts.Close()
		t.Fatalf("NewClientFromJwt: %s", err)
	}
	return ts, client
}

// TestBatchRetrieveSecrets_PartialFailureIsNotTopLevel checks that a 207
// Multi-Status with a mix of 200/403/404 per-secret statuses returns a non-nil
// response and a nil error, with failures readable per secret — never collapsed
// into a top-level error.
func TestBatchRetrieveSecrets_PartialFailureIsNotTopLevel(t *testing.T) {
	ts, c := newSaaSBatchServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusMultiStatus) // 207
		w.Write([]byte(`{"secrets":[
			{"id":"data/ok","value":"s3cr3t","status":200},
			{"id":"data/denied","status":403,"description":"Forbidden"},
			{"id":"data/missing","status":404,"description":"Not Found"}
		]}`))
	})
	defer ts.Close()

	resp, err := c.V2().BatchRetrieveSecrets([]string{"data/ok", "data/denied", "data/missing"})
	require.NoError(t, err, "partial failure must NOT be a top-level error")
	require.NotNil(t, resp)
	assert.Len(t, resp.Secrets, 3)

	byID := map[string]SecretValue{}
	for _, s := range resp.Secrets {
		byID[s.ID] = s
	}
	// Success carries the value; failures carry the per-secret status and the
	// server's error description, so a caller can render each secret's outcome.
	assert.Equal(t, 200, byID["data/ok"].Status)
	assert.Equal(t, "s3cr3t", byID["data/ok"].Value)
	assert.Equal(t, 403, byID["data/denied"].Status)
	assert.Equal(t, "Forbidden", byID["data/denied"].Description)
	assert.Equal(t, 404, byID["data/missing"].Status)
	assert.Equal(t, "Not Found", byID["data/missing"].Description)
}

func TestValidateSecretIdentifiers_OversizedNamesCountAndLimit(t *testing.T) {
	ids := make([]string, MaxSecretsInSingleBatch+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("data/secret%d", i)
	}
	_, err := ValidateSecretIdentifiers(ids)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxSecretsInSingleBatch+1))
}
