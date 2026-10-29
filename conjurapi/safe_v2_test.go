package conjurapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLocalSafeClient(applianceURL string) *ClientV2 {
	return &ClientV2{Client: &Client{config: Config{
		ApplianceURL: applianceURL,
		Account:      "myTestAccount",
		Environment:  EnvironmentSaaS,
	}}}
}

func newSaaSSafeServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
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

func TestSafeValidate(t *testing.T) {
	// Only presence is validated; the server owns the type values.
	assert.Error(t, Safe{}.Validate())                // missing type + name
	assert.Error(t, Safe{Type: "managed"}.Validate()) // missing name
	assert.Error(t, Safe{Name: "n"}.Validate())       // missing type
	assert.NoError(t, Safe{Type: "managed", Name: "n"}.Validate())
	assert.NoError(t, Safe{Type: "dynamic", Name: "n"}.Validate())
	assert.NoError(t, Safe{Type: "anything", Name: "n"}.Validate())
}

func TestSafeURLBuilders(t *testing.T) {
	c := newLocalSafeClient("localhost")

	create, err := c.CreateSafeRequest(Safe{Type: "static", Name: "my-safe", Environment: "prod"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, create.Method)
	assert.Equal(t, "localhost/safes", create.URL.Path)

	get, err := c.GetSafeRequest("static", "my-safe", false)
	require.NoError(t, err)
	assert.Equal(t, "localhost/safes/static/my-safe", get.URL.Path)
	assert.Equal(t, "", get.URL.RawQuery)

	getExt, err := c.GetSafeRequest("static", "my-safe", true)
	require.NoError(t, err)
	assert.Equal(t, "projection=extended", getExt.URL.RawQuery)

	del, err := c.DeleteSafeRequest("static", "my-safe")
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, del.Method)
	assert.Equal(t, "localhost/safes/static/my-safe", del.URL.Path)

	_, err = c.GetSafeRequest("", "n", false)
	assert.Error(t, err)
	_, err = c.GetSafeRequest("static", "", false)
	assert.Error(t, err)
}

func TestSafeURLBuilders_NameIsOneSegment(t *testing.T) {
	c := newLocalSafeClient("localhost")

	// With literal slashes these would reach the permission and secret routes
	// of safe A.
	for name, want := range map[string]string{
		"A/sub":                 "localhost/safes/static/A%2Fsub",
		"A/permissions/group/g": "localhost/safes/static/A%2Fpermissions%2Fgroup%2Fg",
		"A/secrets/s1":          "localhost/safes/static/A%2Fsecrets%2Fs1",
		"a b?c#d%e":             "localhost/safes/static/a%20b%3Fc%23d%25e",
	} {
		get, err := c.GetSafeRequest("static", name, false)
		require.NoError(t, err)
		assert.Equal(t, want, get.URL.EscapedPath(), "get %q", name)

		del, err := c.DeleteSafeRequest("static", name)
		require.NoError(t, err)
		assert.Equal(t, want, del.URL.EscapedPath(), "delete %q", name)

		update, err := c.UpdateSafeRequest(Safe{Type: "static", Name: name})
		require.NoError(t, err)
		assert.Equal(t, want, update.URL.EscapedPath(), "update %q", name)

		replace, err := c.ReplaceSafeRequest(Safe{Type: "static", Name: name})
		require.NoError(t, err)
		assert.Equal(t, want, replace.URL.EscapedPath(), "replace %q", name)
	}
}

func TestSafeName_RejectsTraversal(t *testing.T) {
	c := newLocalSafeClient("localhost")

	for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
		_, err := c.GetSafeRequest("static", bad, false)
		assert.Errorf(t, err, "GetSafeRequest name %q must be rejected", bad)

		_, err = c.DeleteSafeRequest("static", bad)
		assert.Errorf(t, err, "DeleteSafeRequest name %q must be rejected", bad)

		_, err = c.UpdateSafeRequest(Safe{Type: "static", Name: bad})
		assert.Errorf(t, err, "UpdateSafeRequest name %q must be rejected", bad)

		_, err = c.ReplaceSafeRequest(Safe{Type: "static", Name: bad})
		assert.Errorf(t, err, "ReplaceSafeRequest name %q must be rejected", bad)
	}

	// url.PathEscape leaves ".." untouched, so the type needs the guard too.
	for _, badType := range []string{"..", ".", ""} {
		_, err := c.GetSafeRequest(badType, "my-safe", false)
		assert.Errorf(t, err, "GetSafeRequest type %q must be rejected", badType)
	}
}

func TestListSafesRequest_Pagination(t *testing.T) {
	c := newLocalSafeClient("localhost")

	req, err := c.ListSafesRequest(nil)
	require.NoError(t, err)
	assert.Equal(t, "localhost/safes", req.URL.Path)
	assert.Equal(t, "", req.URL.RawQuery)

	req, err = c.ListSafesRequest(&SafeFilter{Limit: 10, Offset: 20})
	require.NoError(t, err)
	assert.Equal(t, "limit=10&offset=20", req.URL.RawQuery)
}

func TestListSafesRequest_SafeTypeFilter(t *testing.T) {
	c := newLocalSafeClient("localhost")

	req, err := c.ListSafesRequest(&SafeFilter{SafeType: "managed"})
	require.NoError(t, err)
	assert.Equal(t, "safe_type eq managed", req.URL.Query().Get("filter"))
	assert.Empty(t, req.URL.Query().Get("type"), "the safe type is not the internal type parameter")

	req, err = c.ListSafesRequest(&SafeFilter{Limit: 5, SafeType: "static", Extended: true})
	require.NoError(t, err)
	assert.Equal(t, "safe_type eq static", req.URL.Query().Get("filter"))
	assert.Equal(t, "5", req.URL.Query().Get("limit"))
	assert.Equal(t, safeExtendedProjection, req.URL.Query().Get("projection"))

	for _, bad := range []string{"managed and name eq x", "man aged", "managed\n"} {
		_, err := c.ListSafesRequest(&SafeFilter{SafeType: bad})
		assert.ErrorContains(t, err, "must not contain whitespace", "%q", bad)
	}
}

func TestCreateSafeRequest_NoServerSetFieldsInBody(t *testing.T) {
	c := newLocalSafeClient("localhost")
	count, replicated := 3, true
	req, err := c.CreateSafeRequest(Safe{Type: "static", Name: "my-safe", Environment: "prod", Description: "d", Annotations: map[string]string{"k": "v"}, CreatedAt: "2026-01-02T03:04:05Z", SecretsCount: &count, Replicated: &replicated})
	require.NoError(t, err)

	body, _ := io.ReadAll(req.Body)
	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &sent))
	assert.Equal(t, map[string]interface{}{"type": "static", "name": "my-safe", "environment": "prod", "description": "d", "annotations": map[string]interface{}{"k": "v"}}, sent)
}

func TestUpdateSafeRequest_SendsOnlySetFields(t *testing.T) {
	c := newLocalSafeClient("localhost")
	req, err := c.UpdateSafeRequest(Safe{Type: "static", Name: "my-safe", Description: "d"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPatch, req.Method)
	assert.Equal(t, "localhost/safes/static/my-safe", req.URL.Path)

	body, _ := io.ReadAll(req.Body)
	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &sent))
	// No name or type (the service rejects them), and no empty fields, so the
	// service keeps the environment and annotations.
	assert.Equal(t, map[string]interface{}{"description": "d"}, sent)
}

func TestReplaceSafeRequest_NoNameOrTypeInBody(t *testing.T) {
	c := newLocalSafeClient("localhost")
	req, err := c.ReplaceSafeRequest(Safe{Type: "static", Name: "my-safe", Description: "d", Environment: "prod"})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, req.Method)
	assert.Equal(t, "localhost/safes/static/my-safe", req.URL.Path)

	body, _ := io.ReadAll(req.Body)
	var sent map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &sent))
	// The service rejects name/type in the replace body.
	assert.NotContains(t, sent, "name")
	assert.NotContains(t, sent, "type")
	assert.Contains(t, sent, "description")
}

func TestSafeExecutors_CRUD(t *testing.T) {
	ts, c := newSaaSSafeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/safes":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"type":"static","name":"my-safe","environment":"prod","replicated":false,"created_at":"2026-01-02T03:04:05Z"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/safes":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"safes":[{"type":"static","name":"s1"},{"type":"static","name":"s2"}],"count":5}`))
		case r.Method == http.MethodGet && r.URL.Path == "/safes/static/my-safe":
			w.WriteHeader(http.StatusOK)
			// The server only returns secrets_count under the extended projection.
			if r.URL.Query().Get("projection") == "extended" {
				w.Write([]byte(`{"type":"static","name":"my-safe","secrets_count":3}`))
			} else {
				w.Write([]byte(`{"type":"static","name":"my-safe"}`))
			}
		case r.Method == http.MethodPatch && r.URL.Path == "/safes/static/my-safe":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"type":"static","name":"my-safe","environment":"prod","description":"patched"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/safes/static/my-safe":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"type":"static","name":"my-safe","description":"updated"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/safes/static/my-safe":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	defer ts.Close()

	created, err := c.V2().CreateSafe(Safe{Type: "static", Name: "my-safe", Environment: "prod"})
	require.NoError(t, err)
	assert.Equal(t, "my-safe", created.Name)
	assert.Equal(t, "2026-01-02T03:04:05Z", created.CreatedAt)

	list, err := c.V2().ListSafes(&SafeFilter{Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, 5, list.Count)
	assert.Len(t, list.Safes, 2)

	got, err := c.V2().GetSafe("static", "my-safe")
	require.NoError(t, err)
	assert.Nil(t, got.SecretsCount)

	gotExt, err := c.V2().GetSafeExtended("static", "my-safe")
	require.NoError(t, err)
	require.NotNil(t, gotExt.SecretsCount)
	assert.Equal(t, 3, *gotExt.SecretsCount)

	updated, err := c.V2().UpdateSafe(Safe{Type: "static", Name: "my-safe", Description: "patched"})
	require.NoError(t, err)
	assert.Equal(t, "patched", updated.Description)
	assert.Equal(t, "prod", updated.Environment)

	replaced, err := c.V2().ReplaceSafe(Safe{Type: "static", Name: "my-safe", Description: "updated"})
	require.NoError(t, err)
	assert.Equal(t, "updated", replaced.Description)

	assert.NoError(t, c.V2().DeleteSafe("static", "my-safe"))
}

func TestSafe_DuplicateCreateConflicts(t *testing.T) {
	ts, c := newSaaSSafeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"conflict","message":"Safe 'dup' already exists"}}`))
	})
	defer ts.Close()

	_, err := c.V2().CreateSafe(Safe{Type: "static", Name: "dup"})
	var conflictErr *response.ConjurError
	require.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, http.StatusConflict, conflictErr.Code)
}

func TestSafe_DeleteReplicatedForbidden(t *testing.T) {
	// The service answers 403 for a replicated safe, unless a member of
	// conjur/replicated-safe-admins passes force. A safe that holds secrets is
	// deleted with them.
	ts, c := newSaaSSafeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"forbidden","message":"Deleting a replicated safe is not allowed"}}`))
	})
	defer ts.Close()

	err := c.V2().DeleteSafe("managed", "replicated")
	var forbiddenErr *response.ConjurError
	require.ErrorAs(t, err, &forbiddenErr)
	assert.Equal(t, http.StatusForbidden, forbiddenErr.Code)
	assert.Equal(t, "forbidden", forbiddenErr.Details.Code)
}

func TestSafe_SelfHostedGate(t *testing.T) {
	c := newLocalSafeClient("https://conjur.example.com")
	c.config.Environment = EnvironmentSH

	_, err := c.CreateSafe(Safe{Type: "static", Name: "n"})
	require.Error(t, err)
	var notSupported *contract.FeatureNotSupportedError
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(contract.CapabilitySafesV2), notSupported.FeatureName)
}

func TestSafes_ValidationErrorWithDetailsList(t *testing.T) {
	ts, client := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(validationFailedBody))
	})
	defer ts.Close()
	c := client.V2()
	want := "422 Unprocessable Entity. value is not present."
	safe := Safe{Type: "dynamic", Name: "s", Annotations: map[string]string{"space": " "}}

	_, err := c.CreateSafe(safe)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	_, err = c.ListSafes(nil)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	err = c.DeleteSafe("dynamic", "s")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())
}
