package conjurapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validJWTAuthToken is a well-formed Conjur access token the client accepts.
const validJWTAuthToken = `{"sub":"admin","iat":"1510753259","protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

// newV2TestClient builds a JWT client for url; an empty environment means Self-Hosted.
func newV2TestClient(t *testing.T, url string, env EnvironmentType) *Client {
	t.Helper()
	config := GetConfigForTest(url)
	config.Environment = env
	config.CredentialStorage = CredentialStorageNone
	client, err := NewClientFromJwt(config)
	require.NoError(t, err)
	return client
}

func TestParseAuthenticatorID(t *testing.T) {
	testCases := []struct {
		name         string
		id           string
		expectedType string
		expectedName string
		expectErr    bool
	}{
		{name: "jwt with name", id: "authn-jwt/myVendor", expectedType: "jwt", expectedName: "myVendor"},
		{name: "iam maps to aws_iam", id: "authn-iam/prod", expectedType: "aws_iam", expectedName: "prod"},
		{name: "cert maps to certificate", id: "authn-cert/svc", expectedType: "certificate", expectedName: "svc"},
		{name: "gcp singleton", id: "authn-gcp", expectedType: "gcp", expectedName: ""},
		{name: "gcp short singleton", id: "gcp", expectedType: "gcp", expectedName: ""},
		{name: "type without authn prefix", id: "jwt/svc", expectedType: "jwt", expectedName: "svc"},
		{name: "slash in the name", id: "authn-jwt/a/b", expectedType: "jwt", expectedName: "a/b"},
		{name: "empty", id: "", expectErr: true},
		{name: "missing name", id: "authn-jwt", expectErr: true},
		{name: "trailing slash only", id: "authn-jwt/", expectErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authType, name, err := ParseAuthenticatorID(tc.id)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedType, authType)
			assert.Equal(t, tc.expectedName, name)
		})
	}
}

func TestClientV2_UpdateAuthenticatorRequest(t *testing.T) {
	client := newV2TestClient(t, "localhost", EnvironmentSaaS)

	t.Run("sends only the provided fields and uses the finalized v2 header", func(t *testing.T) {
		req, err := client.V2().UpdateAuthenticatorRequest("jwt", "myVendor", &AuthenticatorPatch{
			Enabled: Bool(true),
			Data: map[string]interface{}{
				"issuer": "https://example.com",
			},
		})
		require.NoError(t, err)

		assert.Equal(t, http.MethodPatch, req.Method)
		assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		assert.Equal(t, "localhost/authenticators/jwt/myVendor", req.URL.Path)

		body, _ := io.ReadAll(req.Body)
		var payload map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &payload))
		assert.Equal(t, true, payload["enabled"])
		assert.Contains(t, payload, "data")
		assert.NotContains(t, payload, "annotations")
	})

	t.Run("sends annotations and nested data as given", func(t *testing.T) {
		req, err := client.V2().UpdateAuthenticatorRequest("jwt", "myVendor", &AuthenticatorPatch{
			Annotations: map[string]string{"team": "sdk"},
			Data: map[string]interface{}{
				"audience": "conjur",
				"identity": map[string]interface{}{"token_app_property": "sub"},
			},
		})
		require.NoError(t, err)
		body, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{"annotations":{"team":"sdk"},"data":{"audience":"conjur","identity":{"token_app_property":"sub"}}}`, string(body))
	})

	t.Run("nil patch marshals to an empty object", func(t *testing.T) {
		req, err := client.V2().UpdateAuthenticatorRequest("jwt", "myVendor", nil)
		require.NoError(t, err)
		body, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, "{}", string(body))
	})
}

// Self-Hosted's V2 PATCH only takes "enabled", so anything else is refused
// before a request is built.
func TestClientV2_UpdateAuthenticatorRequest_SelfHosted(t *testing.T) {
	client := newV2TestClient(t, "localhost", EnvironmentSH)

	t.Run("enabled alone is sent", func(t *testing.T) {
		req, err := client.V2().UpdateAuthenticatorRequest("jwt", "myVendor", &AuthenticatorPatch{Enabled: Bool(false)})
		require.NoError(t, err)
		assert.Equal(t, "localhost/authenticators/account/jwt/myVendor", req.URL.Path)
		body, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{"enabled":false}`, string(body))
	})

	refused := []struct {
		name  string
		patch *AuthenticatorPatch
		want  string
	}{
		{
			name:  "data",
			patch: &AuthenticatorPatch{Data: map[string]interface{}{"audience": "conjur"}},
			want:  `Updating an authenticator's data is not supported in Idira Secrets Manager/Conjur OSS; only "enabled" can be changed`,
		},
		{
			name:  "annotations and data alongside enabled",
			patch: &AuthenticatorPatch{Enabled: Bool(true), Annotations: map[string]string{"a": "b"}, Data: map[string]interface{}{"audience": "conjur"}},
			want:  `Updating an authenticator's annotations and data is not supported in Idira Secrets Manager/Conjur OSS; only "enabled" can be changed`,
		},
		{
			name:  "nothing",
			patch: nil,
			want:  `An authenticator update must set "enabled" in Idira Secrets Manager/Conjur OSS, the only setting it can change`,
		},
		{
			name:  "empty annotations and data only",
			patch: &AuthenticatorPatch{Annotations: map[string]string{}, Data: map[string]interface{}{}},
			want:  `An authenticator update must set "enabled" in Idira Secrets Manager/Conjur OSS, the only setting it can change`,
		},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			req, err := client.V2().UpdateAuthenticatorRequest("jwt", "myVendor", tc.patch)
			assert.Nil(t, req)
			assert.EqualError(t, err, tc.want)
		})
	}

	t.Run("a refused update reaches no server", func(t *testing.T) {
		server, handler := newAuthenticatorMockServer(t)
		defer server.Close()
		client := newV2TestClient(t, server.URL, EnvironmentSH)

		_, err := client.V2().UpdateAuthenticator("jwt", "myVendor", &AuthenticatorPatch{Data: map[string]interface{}{"audience": "x"}})
		require.Error(t, err)
		assert.Empty(t, handler.lastMethod)
	})
}

func TestClientV2_ListAuthenticatorsRequest_Pagination(t *testing.T) {
	client := newV2TestClient(t, "localhost", EnvironmentSaaS)

	t.Run("no filter has no query", func(t *testing.T) {
		req, err := client.V2().ListAuthenticatorsRequest(nil)
		require.NoError(t, err)
		assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
		assert.Empty(t, req.URL.RawQuery)
	})

	t.Run("limit and offset become query params", func(t *testing.T) {
		req, err := client.V2().ListAuthenticatorsRequest(&AuthenticatorFilter{Limit: 25, Offset: 50})
		require.NoError(t, err)
		assert.Equal(t, "25", req.URL.Query().Get("limit"))
		assert.Equal(t, "50", req.URL.Query().Get("offset"))
	})
}

// newAuthenticatorListServer serves n authenticators and ignores paging, as SaaS does.
func newAuthenticatorListServer(t *testing.T, n int) (*httptest.Server, *url.Values) {
	query := &url.Values{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info":
			w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
			return
		case "/authn-jwt/jwt_service/account/authenticate":
			w.Write([]byte(validJWTAuthToken))
			return
		}
		*query = r.URL.Query()
		list := AuthenticatorListResponse{Count: n}
		for i := 0; i < n; i++ {
			list.Authenticators = append(list.Authenticators, AuthenticatorResponse{
				AuthenticatorBase: AuthenticatorBase{Type: "jwt", Name: fmt.Sprintf("a%d", i)},
			})
		}
		require.NoError(t, json.NewEncoder(w).Encode(list))
	})
	return httptest.NewServer(mux), query
}

func authenticatorNames(list *AuthenticatorListResponse) []string {
	names := []string{}
	for _, a := range list.Authenticators {
		names = append(names, a.Name)
	}
	return names
}

func TestClientV2_ListAuthenticators_PassesPaging(t *testing.T) {
	for _, env := range []EnvironmentType{EnvironmentSaaS, EnvironmentSH} {
		t.Run(string(env), func(t *testing.T) {
			server, query := newAuthenticatorListServer(t, 5)
			defer server.Close()
			client := newV2TestClient(t, server.URL, env)

			list, err := client.V2().ListAuthenticators(&AuthenticatorFilter{Limit: 2, Offset: 1})
			require.NoError(t, err)
			assert.Equal(t, "2", query.Get("limit"))
			assert.Equal(t, "1", query.Get("offset"))
			// Paging is left to the server, so the response is returned as is.
			assert.Equal(t, []string{"a0", "a1", "a2", "a3", "a4"}, authenticatorNames(list))
			assert.Equal(t, 5, list.Count)
		})
	}
}

// authenticatorMockHandler records the last request and serves v2 and v1 enable endpoints.
type authenticatorMockHandler struct {
	t             *testing.T
	lastMethod    string
	lastPath      string
	lastRawPath   string
	lastAccept    string
	lastBody      []byte
	conflictOnPUT bool
}

func newAuthenticatorMockServer(t *testing.T) (*httptest.Server, *authenticatorMockHandler) {
	h := &authenticatorMockHandler{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Server version for the capability check.
		if r.URL.Path == "/info" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
			return
		}
		// JWT authentication.
		if r.URL.Path == "/authn-jwt/jwt_service/account/authenticate" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(validJWTAuthToken))
			return
		}

		h.lastMethod = r.Method
		h.lastPath = r.URL.Path
		h.lastRawPath = r.URL.EscapedPath()
		h.lastAccept = r.Header.Get("Accept")
		h.lastBody, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"type":"jwt","name":"myVendor","enabled":false}`))
	})
	return httptest.NewServer(mux), h
}

func TestClient_SetAuthenticatorEnabled_RoutesToV2OnSaaS(t *testing.T) {
	testCases := []struct {
		id   string
		path string
	}{
		{id: "authn-jwt/myVendor", path: "/authenticators/jwt/myVendor"},
		{id: "authn-gcp", path: "/authenticators/gcp/default"},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			server, handler := newAuthenticatorMockServer(t)
			defer server.Close()

			client := newV2TestClient(t, server.URL, EnvironmentSaaS)

			err := client.SetAuthenticatorEnabled(tc.id, false)
			require.NoError(t, err)

			assert.Equal(t, http.MethodPatch, handler.lastMethod)
			assert.Equal(t, tc.path, handler.lastPath)
			assert.Equal(t, v2APIHeaderBeta, handler.lastAccept)

			var payload map[string]interface{}
			require.NoError(t, json.Unmarshal(handler.lastBody, &payload))
			assert.Equal(t, false, payload["enabled"])
		})
	}
}

func TestClient_SetAuthenticatorEnabled_RoutesToV1OnSelfHosted(t *testing.T) {
	server, handler := newAuthenticatorMockServer(t)
	defer server.Close()

	client := newV2TestClient(t, server.URL, EnvironmentSH)

	err := client.SetAuthenticatorEnabled("authn-jwt/myVendor", true)
	require.NoError(t, err)

	// v1 endpoint: PATCH /authn-jwt/<service>/<account>, form-encoded, no v2 header.
	assert.Equal(t, http.MethodPatch, handler.lastMethod)
	assert.Equal(t, "/authn-jwt/myVendor/account", handler.lastPath)
	assert.NotEqual(t, v2APIHeaderBeta, handler.lastAccept)
	assert.Contains(t, string(handler.lastBody), "enabled=true")
}

func TestClient_SetAuthenticatorEnabled_MapsTypesForV1(t *testing.T) {
	// v1 uses the short type names, so the URL must be authn-iam, not
	// authn-aws_iam, and the GCP one has no name.
	testCases := []struct {
		id   string
		path string
	}{
		{id: "authn-iam/prod", path: "/authn-iam/prod/account"},
		{id: "authn-cert/svc", path: "/authn-cert/svc/account"},
		{id: "authn-gcp", path: "/authn-gcp/account"},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			server, handler := newAuthenticatorMockServer(t)
			defer server.Close()

			client := newV2TestClient(t, server.URL, EnvironmentSH)

			err := client.SetAuthenticatorEnabled(tc.id, true)
			require.NoError(t, err)
			assert.Equal(t, tc.path, handler.lastPath)
		})
	}
}

func TestClient_SetAuthenticatorEnabled_InvalidID(t *testing.T) {
	client := newV2TestClient(t, "localhost", EnvironmentSaaS)
	err := client.SetAuthenticatorEnabled("not-a-valid-id", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authenticator ID format")
}

// authenticatorItemRequestBuilders covers every v2 request that puts a
// caller-supplied type and name into the URL path.
func authenticatorItemRequestBuilders(client *Client) map[string]func(authenticatorType, name string) (*http.Request, error) {
	return map[string]func(authenticatorType, name string) (*http.Request, error){
		"get": client.V2().GetAuthenticatorRequest,
		"update": func(authenticatorType, name string) (*http.Request, error) {
			return client.V2().UpdateAuthenticatorRequest(authenticatorType, name, &AuthenticatorPatch{Enabled: Bool(true)})
		},
		"delete": client.V2().DeleteAuthenticatorRequest,
	}
}

// authenticatorItemMethods is the HTTP method of each authenticatorItemRequestBuilders request.
var authenticatorItemMethods = map[string]string{
	"get":    http.MethodGet,
	"update": http.MethodPatch,
	"delete": http.MethodDelete,
}

func TestClientV2_AuthenticatorRequests_RejectPathTraversal(t *testing.T) {
	testCases := []struct {
		name              string
		authenticatorType string
		authenticatorName string
	}{
		{name: "dot-dot name escapes the collection", authenticatorType: "jwt", authenticatorName: "../../branches/data/prod"},
		{name: "dot-dot inside the name", authenticatorType: "jwt", authenticatorName: "a/../b"},
		{name: "dot name", authenticatorType: "jwt", authenticatorName: "."},
		{name: "empty name segment", authenticatorType: "jwt", authenticatorName: "a//b"},
		{name: "trailing slash", authenticatorType: "jwt", authenticatorName: "a/"},
		{name: "dot-dot type", authenticatorType: "..", authenticatorName: "myVendor"},
	}

	for _, env := range []EnvironmentType{EnvironmentSaaS, EnvironmentSH} {
		client := newV2TestClient(t, "localhost", env)
		for builderName, build := range authenticatorItemRequestBuilders(client) {
			for _, tc := range testCases {
				t.Run(string(env)+"/"+builderName+"/"+tc.name, func(t *testing.T) {
					_, err := build(tc.authenticatorType, tc.authenticatorName)
					require.Error(t, err)
					assert.Contains(t, err.Error(), `must not be empty, ".", or ".."`)
				})
			}
		}
	}
}

func TestClientV2_AuthenticatorRequests_EscapePath(t *testing.T) {
	testCases := []struct {
		name              string
		env               EnvironmentType
		authenticatorType string
		authenticatorName string
		expectedPath      string
	}{
		{name: "plain name on SaaS", env: EnvironmentSaaS, authenticatorType: "jwt", authenticatorName: "myVendor",
			expectedPath: "localhost/authenticators/jwt/myVendor"},
		{name: "plain name on Self-Hosted", env: EnvironmentSH, authenticatorType: "jwt", authenticatorName: "myVendor",
			expectedPath: "localhost/authenticators/account/jwt/myVendor"},
		{name: "slash in the name keeps the path structure", env: EnvironmentSaaS, authenticatorType: "jwt", authenticatorName: "a/b",
			expectedPath: "localhost/authenticators/jwt/a/b"},
		{name: "query and fragment characters stay in the path", env: EnvironmentSaaS, authenticatorType: "jwt", authenticatorName: "svc?limit=1#x",
			expectedPath: "localhost/authenticators/jwt/svc%3Flimit=1%23x"},
		{name: "percent is escaped", env: EnvironmentSH, authenticatorType: "jwt", authenticatorName: "a%2F..",
			expectedPath: "localhost/authenticators/account/jwt/a%252F.."},
		{name: "slash in the type stays one segment", env: EnvironmentSaaS, authenticatorType: "jwt/x", authenticatorName: "svc",
			expectedPath: "localhost/authenticators/jwt%2Fx/svc"},
		{name: "gcp without a name is default on SaaS", env: EnvironmentSaaS, authenticatorType: "gcp", authenticatorName: "",
			expectedPath: "localhost/authenticators/gcp/default"},
		{name: "gcp without a name is default on Self-Hosted", env: EnvironmentSH, authenticatorType: "gcp", authenticatorName: "",
			expectedPath: "localhost/authenticators/account/gcp/default"},
	}

	for _, tc := range testCases {
		client := newV2TestClient(t, "localhost", tc.env)
		for builderName, build := range authenticatorItemRequestBuilders(client) {
			t.Run(builderName+"/"+tc.name, func(t *testing.T) {
				req, err := build(tc.authenticatorType, tc.authenticatorName)
				require.NoError(t, err)
				assert.Equal(t, authenticatorItemMethods[builderName], req.Method)
				assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
				assert.Equal(t, tc.expectedPath, req.URL.EscapedPath())
				assert.Empty(t, req.URL.RawQuery)
				assert.Empty(t, req.URL.Fragment)
			})
		}
	}

	// Create and list take no type or name; their path is the collection.
	for _, env := range []EnvironmentType{EnvironmentSaaS, EnvironmentSH} {
		client := newV2TestClient(t, "localhost", env)
		collection := "localhost/authenticators"
		if env == EnvironmentSH {
			collection += "/account"
		}

		t.Run("create/"+string(env), func(t *testing.T) {
			req, err := client.V2().CreateAuthenticatorRequest(&AuthenticatorBase{Type: "jwt", Name: "myVendor"})
			require.NoError(t, err)
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, collection, req.URL.EscapedPath())
		})

		t.Run("list/"+string(env), func(t *testing.T) {
			req, err := client.V2().ListAuthenticatorsRequest(nil)
			require.NoError(t, err)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
			assert.Equal(t, collection, req.URL.EscapedPath())
		})
	}
}

func TestClientV2_DeleteAuthenticator_TraversalSendsNoRequest(t *testing.T) {
	for _, env := range []EnvironmentType{EnvironmentSaaS, EnvironmentSH} {
		t.Run(string(env), func(t *testing.T) {
			server, handler := newAuthenticatorMockServer(t)
			defer server.Close()

			client := newV2TestClient(t, server.URL, env)

			err := client.V2().DeleteAuthenticator("jwt", "../../branches/data/prod")
			require.Error(t, err)
			assert.Empty(t, handler.lastMethod, "no request should reach the server")
		})
	}
}

func TestClient_AuthenticatorManagementRequests_EscapePath(t *testing.T) {
	client := newV2TestClient(t, "localhost", EnvironmentSH)

	builders := map[string]func(authenticatorType, serviceID string) (*http.Request, error){
		"enable": func(authenticatorType, serviceID string) (*http.Request, error) {
			return client.EnableAuthenticatorRequest(authenticatorType, serviceID, true)
		},
		"status": client.AuthenticatorStatusRequest,
	}

	testCases := []struct {
		name              string
		authenticatorType string
		serviceID         string
		expectedPath      string
	}{
		{name: "plain service ID", authenticatorType: "jwt", serviceID: "myVendor",
			expectedPath: "localhost/authn-jwt/myVendor/account"},
		{name: "gcp has no service ID", authenticatorType: "gcp", serviceID: "",
			expectedPath: "localhost/authn-gcp/account"},
		{name: "query and fragment characters stay in the path", authenticatorType: "jwt", serviceID: "svc?x=1#y",
			expectedPath: "localhost/authn-jwt/svc%3Fx=1%23y/account"},
	}

	for builderName, build := range builders {
		for _, tc := range testCases {
			t.Run(builderName+"/"+tc.name, func(t *testing.T) {
				req, err := build(tc.authenticatorType, tc.serviceID)
				require.NoError(t, err)
				expectedPath := tc.expectedPath
				if builderName == "status" {
					expectedPath += "/status"
				}
				assert.Equal(t, expectedPath, req.URL.EscapedPath())
				assert.Empty(t, req.URL.RawQuery)
			})
		}

		t.Run(builderName+"/rejects path traversal", func(t *testing.T) {
			_, err := build("jwt", "../../../policies/account/policy/root")
			require.Error(t, err)
			assert.Contains(t, err.Error(), `must not be empty, ".", or ".."`)
		})
	}
}

func TestClient_SetAuthenticatorEnabled_TraversalSendsNoRequest(t *testing.T) {
	for _, env := range []EnvironmentType{EnvironmentSaaS, EnvironmentSH} {
		t.Run(string(env), func(t *testing.T) {
			server, handler := newAuthenticatorMockServer(t)
			defer server.Close()

			client := newV2TestClient(t, server.URL, env)

			err := client.SetAuthenticatorEnabled("authn-jwt/../../branches/data/prod", false)
			require.Error(t, err)
			assert.Empty(t, handler.lastMethod, "no request should reach the server")
		})
	}
}

func TestCreateAuthenticator_DuplicateConflicts(t *testing.T) {
	testCases := []struct {
		env  EnvironmentType
		body string
	}{
		{env: EnvironmentSaaS, body: `{"error":{"code":"conflict","message":"The myVendor authenticator already exists."}}`},
		// Self-Hosted sends a flat body with the status as its code.
		{env: EnvironmentSH, body: `{"code":"409","message":"The authenticator already exists."}`},
	}

	for _, tc := range testCases {
		t.Run(string(tc.env), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/info" {
					w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
					return
				}
				if r.URL.Path == "/authn-jwt/jwt_service/account/authenticate" {
					w.Write([]byte(validJWTAuthToken))
					return
				}
				// Create conflict.
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := newV2TestClient(t, server.URL, tc.env)

			_, err := client.V2().CreateAuthenticator(&AuthenticatorBase{Type: "jwt", Name: "myVendor"})
			var conflictErr *response.ConjurError
			require.ErrorAs(t, err, &conflictErr, "duplicate create must surface a *response.ConjurError")
			assert.Equal(t, http.StatusConflict, conflictErr.Code, "duplicate create must be a distinguishable 409 conflict")
			assert.Contains(t, err.Error(), "already exists.")
		})
	}

	// A non-conflict error must not be misclassified.
	var notConjur *response.ConjurError
	assert.False(t, errors.As(io.EOF, &notConjur))
}

// Secrets Manager SaaS leaves "branch" out of authenticator responses, so a
// re-encoded response must leave it out too rather than add "branch": "".
func TestAuthenticatorResponse_BranchOnlyWhenSet(t *testing.T) {
	saas, err := json.Marshal(AuthenticatorResponse{AuthenticatorBase: AuthenticatorBase{Type: "jwt", Name: "myVendor"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"jwt","name":"myVendor"}`, string(saas))

	selfHosted, err := json.Marshal(AuthenticatorResponse{
		AuthenticatorBase: AuthenticatorBase{Type: "jwt", Name: "myVendor"},
		Branch:            "conjur/authn-jwt",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"jwt","name":"myVendor","branch":"conjur/authn-jwt"}`, string(selfHosted))
}

func TestAuthenticatorResponse_CreatedAt(t *testing.T) {
	// A GCP authenticator as Secrets Manager SaaS returns it.
	var got AuthenticatorResponse
	require.NoError(t, json.Unmarshal([]byte(`{"type":"gcp","name":"default","enabled":false,"created_at":"2026-08-26T13:35:19.104+00:00"}`), &got))
	assert.Equal(t, "2026-08-26T13:35:19.104+00:00", got.CreatedAt)
}
