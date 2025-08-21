package conjurapi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_EnableAuthenticator(t *testing.T) {
	testCases := []struct {
		name      string
		serviceID string
		expectErr bool
	}{
		{
			name:      "Enables/disables a valid authenticator successfully",
			serviceID: "test",
			expectErr: false,
		},
		{
			name:      "Fails to enable/disable if authenticator doesn't exist or user doesn't have access",
			serviceID: "non-existent",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			err = utils.SetupWithAuthenticator("jwt", jwtAuthenticatorPolicy, jwtRolePolicy)
			require.NoError(t, err)

			conjur := utils.Client()

			// Enable
			err = conjur.EnableAuthenticator("jwt", tc.serviceID, true)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Disable
			err = conjur.EnableAuthenticator("jwt", tc.serviceID, false)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClient_AuthenticatorStatus(t *testing.T) {
	testCases := []struct {
		name               string
		authnType          string
		serviceID          string
		expectErr          bool
		expectedResponse   *AuthenticatorStatusResponse
		authenticatorSetup func(t *testing.T, utils TestUtils)
	}{
		{
			name:      "Returns error if authenticator type doesn't exist",
			authnType: "non-existent",
			serviceID: "test",
			expectErr: true,
		},
		{
			name:      "Returns error status if authenticator service doesn't exist",
			authnType: "jwt",
			serviceID: "non-existent",
			// The response code of this status endpoint is different between Conjur
			// cloud and self-hosted.
			expectErr: !isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")),
			expectedResponse: &AuthenticatorStatusResponse{
				Status: "error",
				Error:  "#<Errors::Authentication::Security::WebserviceNotFound: CONJ00005E Webservice 'authn-jwt/non-existent/status' not found>",
			},
		},
		{
			name:      "Returns error status if required variables are not set",
			authnType: "jwt",
			serviceID: "test",
			authenticatorSetup: func(t *testing.T, utils TestUtils) {
				conjur := utils.Client()
				err := conjur.EnableAuthenticator("jwt", "test", true)
				require.NoError(t, err)
			},
			expectErr: false,
			expectedResponse: &AuthenticatorStatusResponse{
				Status: "error",
				Error:  "#<Errors::Conjur::RequiredSecretMissing: CONJ00037E Missing value for resource: conjur:variable:conjur/authn-jwt/test/public-keys>",
			},
		},
		{
			name:      "Returns disabled status if authenticator is not enabled",
			authnType: "jwt",
			serviceID: "test",
			authenticatorSetup: func(t *testing.T, utils TestUtils) {
				jwks := "{\"type\":\"jwks\",\"value\":" + os.Getenv("PUBLIC_KEYS") + "}"
				conjur := utils.Client()
				conjur.AddSecret("conjur/authn-jwt/test/public-keys", jwks)
				conjur.AddSecret("conjur/authn-jwt/test/issuer", "jwt-server")
				conjur.AddSecret("conjur/authn-jwt/test/audience", "conjur")
				conjur.AddSecret("conjur/authn-jwt/test/token-app-property", "email")
				conjur.AddSecret("conjur/authn-jwt/test/identity-path", "data/test/jwt-apps")
				err := conjur.EnableAuthenticator("jwt", "test", false)
				require.NoError(t, err)
			},
			expectErr: false,
			expectedResponse: &AuthenticatorStatusResponse{
				Status: "error",
				Error:  "#<Errors::Authentication::Security::AuthenticatorNotWhitelisted: CONJ00004E 'authn-jwt/test' is not enabled>",
			},
		},
		{
			name:      "Returns ok status if authenticator is enabled",
			authnType: "jwt",
			serviceID: "test",
			authenticatorSetup: func(t *testing.T, utils TestUtils) {
				jwks := "{\"type\":\"jwks\",\"value\":" + os.Getenv("PUBLIC_KEYS") + "}"
				conjur := utils.Client()
				conjur.AddSecret("conjur/authn-jwt/test/public-keys", jwks)
				conjur.AddSecret("conjur/authn-jwt/test/issuer", "jwt-server")
				conjur.AddSecret("conjur/authn-jwt/test/audience", "conjur")
				conjur.AddSecret("conjur/authn-jwt/test/token-app-property", "email")
				conjur.AddSecret("conjur/authn-jwt/test/identity-path", "data/test/jwt-apps")
				err := conjur.EnableAuthenticator("jwt", "test", true)
				require.NoError(t, err)
			},
			expectErr: false,
			expectedResponse: &AuthenticatorStatusResponse{
				Status: "ok",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			err = utils.SetupWithAuthenticator("jwt", jwtAuthenticatorPolicy, jwtRolePolicy)
			require.NoError(t, err)

			// Run any case-specific setup
			if tc.authenticatorSetup != nil {
				tc.authenticatorSetup(t, utils)
			}

			conjur := utils.Client()

			authnStatus, err := conjur.AuthenticatorStatus(tc.authnType, tc.serviceID)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.EqualValues(t, tc.expectedResponse, authnStatus)
			}
		})
	}
}
func TestClient_AuthenticatorCRUD(t *testing.T) {
	testCases := []struct {
		name             string
		authenticator    *AuthenticatorBase
		expectErr        bool
		expectedResponse *AuthenticatorResponse
	}{
		{
			name: "Returns authenticator JSON if successful (default values)",
			authenticator: &AuthenticatorBase{
				Type: "jwt",
				Name: "test-authenticator-default-vals",
				Data: map[string]interface{}{
					"audience": "conjur-cloud",
					"jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
					"issuer":   "https://token.actions.githubusercontent.com",
					"identity": map[string]interface{}{
						"identity_path":      "data/github-apps",
						"token_app_property": "repository_id",
					},
				},
			},
			expectErr: false,
			expectedResponse: &AuthenticatorResponse{
				Branch: "conjur/authn-jwt",
				AuthenticatorBase: AuthenticatorBase{
					Type:    "jwt",
					Name:    "test-authenticator-default-vals",
					Enabled: Bool(true),
					Owner: &AuthOwner{
						// Ownership behavior varies between Conjur Cloud and self-hosted currently,
						// so we end up ignoring this in the test assertion.
						ID:   "conjur/authn-jwt/test-authenticator-default-vals",
						Kind: "policy",
					},
					Data: map[string]interface{}{
						"audience": "conjur-cloud",
						"jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
						"issuer":   "https://token.actions.githubusercontent.com",
						"identity": map[string]interface{}{
							"identity_path":      "data/github-apps",
							"token_app_property": "repository_id",
						},
					},
				},
			},
		},
		{
			name: "Returns authenticator JSON if successful (optional values)",
			authenticator: &AuthenticatorBase{
				Type:    "jwt",
				Name:    "test-authenticator-optional-vals",
				Enabled: Bool(true),
				Owner: &AuthOwner{
					ID:   "PLACEHOLDER",
					Kind: "user",
				},
				Data: map[string]interface{}{
					"audience": "conjur-cloud",
					"jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
					"issuer":   "https://token.actions.githubusercontent.com",
					"identity": map[string]interface{}{
						"identity_path":      "data/github-apps",
						"token_app_property": "repository_id",
					},
				},
				Annotations: map[string]string{
					"annotation-key": "annotation-value",
					"description":    "This is a test authenticator",
				},
			},
			expectErr: false,
			expectedResponse: &AuthenticatorResponse{
				Branch: "conjur/authn-jwt",
				AuthenticatorBase: AuthenticatorBase{
					Type:    "jwt",
					Name:    "test-authenticator-optional-vals",
					Enabled: Bool(true),
					Owner: &AuthOwner{
						// Ownership behavior varies between Conjur Cloud and self-hosted currently,
						// so we end up ignoring this in the test assertion.
						ID:   "PLACEHOLDER",
						Kind: "user",
					},
					Data: map[string]interface{}{
						"audience": "conjur-cloud",
						"jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
						"issuer":   "https://token.actions.githubusercontent.com",
						"identity": map[string]interface{}{
							"identity_path":      "data/github-apps",
							"token_app_property": "repository_id",
						},
					},
					Annotations: map[string]string{
						"annotation-key": "annotation-value",
						"description":    "This is a test authenticator",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			utils, err := NewTestUtils(&Config{})
			require.NoError(t, err)

			// Ensure there is a conjur/authn-jwt branch by creating an arbitrary authenticator
			err = utils.SetupWithAuthenticator("jwt", jwtAuthenticatorPolicy, jwtRolePolicy)
			require.NoError(t, err)
			conjur := utils.Client()

			// Replace placeholder owner ID with actual ID
			if tc.authenticator.Owner != nil && tc.authenticator.Owner.ID == "PLACEHOLDER" {
				tc.authenticator.Owner.ID = utils.AdminUser()
				tc.expectedResponse.Owner.ID = utils.AdminUser()
			}

			// Test CREATE
			authenticatorResponse, err := conjur.V2.CreateAuthenticator(tc.authenticator)
			require.NoError(t, err)
			assert.EqualValues(t, normalize(tc.expectedResponse), normalize(authenticatorResponse))

			// Test LIST (expect at least two authenticators from test setup + CREATE)
			authenticatorsList, err := conjur.V2.ListAuthenticators()
			require.NoError(t, err)
			assert.GreaterOrEqual(t, authenticatorsList.Count, 2)
			assert.GreaterOrEqual(t, len(authenticatorsList.Authenticators), 2)

			// Test READ (expect the same JSON from CREATE)
			authenticatorResponse, err = conjur.V2.GetAuthenticator("jwt", tc.authenticator.Name)
			require.NoError(t, err)
			assert.EqualValues(t, normalize(tc.expectedResponse), normalize(authenticatorResponse))

			// Test UPDATE (disable the authenticator)
			authenticatorResponse, err = conjur.V2.UpdateAuthenticator("jwt", tc.authenticator.Name, false)
			require.NoError(t, err)
			assert.EqualValues(t, false, normalize(authenticatorResponse).Enabled)

			// Test DELETE
			err = conjur.V2.DeleteAuthenticator("jwt", tc.authenticator.Name)
			require.NoError(t, err)
		})
	}
}

// NormalizedAuthenticatorResponse flattens pointer fields so we can compare by value.
type NormalizedAuthenticatorResponse struct {
	Type        string
	Subtype     string
	Name        string
	Enabled     bool
	Owner       map[string]string
	Data        map[string]interface{}
	Annotations map[string]string
	Branch      string
}

func normalize(resp *AuthenticatorResponse) NormalizedAuthenticatorResponse {
	var subtype string
	if resp.Subtype != nil {
		subtype = *resp.Subtype
	}

	var enabled bool
	if resp.Enabled != nil {
		enabled = *resp.Enabled
	}

	// Ownership behavior is currently inconsistent between Conjur Cloud and self-hosted
	// For now we set it to 'nil' so it doesn't get compared in the response JSON
	// var owner map[string]string
	// if resp.Owner != nil {
	// 	owner = map[string]string{
	// 		"ID":   resp.Owner.ID,
	// 		"Kind": resp.Owner.Kind,
	// 	}
	// }

	return NormalizedAuthenticatorResponse{
		Type:        resp.Type,
		Subtype:     subtype,
		Name:        resp.Name,
		Enabled:     enabled,
		Owner:       nil,
		Data:        resp.Data,
		Annotations: resp.Annotations,
		Branch:      resp.Branch,
	}
}
