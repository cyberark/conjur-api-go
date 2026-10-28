package conjurapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLocalAnnotationClient(applianceURL string) *ClientV2 {
	return &ClientV2{Client: &Client{config: Config{
		ApplianceURL: applianceURL,
		Account:      "myTestAccount",
		Environment:  EnvironmentSaaS,
	}}}
}

func newSaaSAnnotationServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
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

func TestSupportedAnnotationKinds(t *testing.T) {
	assert.Equal(t,
		[]AnnotationKind{AnnotationKindBranch, AnnotationKindGroup, AnnotationKindWorkload},
		SupportedAnnotationKinds(),
	)
}

func TestDeleteAnnotationRequest_PerKindURL(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	testCases := []struct {
		kind AnnotationKind
		id   string
		name string
		path string
	}{
		{AnnotationKindWorkload, "data/my-workload", "owner", "localhost/workloads/data/my-workload/annotations/owner"},
		{AnnotationKindGroup, "data/my-group", "team", "localhost/groups/data/my-group/annotations/team"},
		{AnnotationKindBranch, "data/my-branch", "env", "localhost/branches/data/my-branch/annotations/env"},
		{AnnotationKindWorkload, "data/my-workload", "x:y", "localhost/workloads/data/my-workload/annotations/x:y"},
		{AnnotationKindGroup, "data/my-group", "x:y", "localhost/groups/data/my-group/annotations/x:y"},
		{AnnotationKindBranch, "data/my-branch", "x:y", "localhost/branches/data/my-branch/annotations/x:y"},
	}
	for _, tc := range testCases {
		t.Run(string(tc.kind)+" "+tc.name, func(t *testing.T) {
			req, err := c.DeleteAnnotationRequest(tc.kind, tc.id, tc.name)
			require.NoError(t, err)
			assert.Equal(t, http.MethodDelete, req.Method)
			assert.Equal(t, tc.path, req.URL.Path)
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
		})
	}
}

func TestDeleteAnnotationRequest_Validation(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	_, err := c.DeleteAnnotationRequest(AnnotationKind("safe"), "x", "n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported annotation kind")

	_, err = c.DeleteAnnotationRequest(AnnotationKindBranch, "", "n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifier")

	_, err = c.DeleteAnnotationRequest(AnnotationKindBranch, "data/b", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "annotation name")

	_, err = c.DeleteAnnotationRequest(AnnotationKindBranch, "data/b", " \t")
	assert.ErrorContains(t, err, "Annotation name must not be only whitespace")
}

func TestDeleteAnnotationRequest_RejectsTraversal(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
		_, err := c.DeleteAnnotationRequest(AnnotationKindBranch, bad, "owner")
		assert.Errorf(t, err, "resource identifier %q must be rejected", bad)
	}

	// Slashes in the name are escaped, but the server still resolves a whole
	// "." or "..", deleting the resource for "..", and the SaaS gateway
	// refuses "../" and "..\" anywhere in it.
	for _, kind := range SupportedAnnotationKinds() {
		for _, bad := range []string{"..", ".", "../a", "a/../b", "a../b", "a/../", `..\b`} {
			_, err := c.DeleteAnnotationRequest(kind, "data/b", bad)
			assert.Errorf(t, err, "%s: annotation name %q must be rejected", kind, bad)
		}
	}
}

func TestDeleteAnnotationRequest_EscapesSlashInName(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	testCases := []struct {
		kind AnnotationKind
		path string
	}{
		{AnnotationKindWorkload, "localhost/workloads/data/x/annotations/a%2F.."},
		{AnnotationKindGroup, "localhost/groups/data/x/annotations/a%2F.."},
		{AnnotationKindBranch, "localhost/branches/data/x/annotations/a%2F.."},
	}
	for _, tc := range testCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			req, err := c.DeleteAnnotationRequest(tc.kind, "data/x", "a/..")
			require.NoError(t, err)
			assert.Equal(t, tc.path, req.URL.EscapedPath())
		})
	}
}

func TestDeleteAnnotationRequest_EscapesSpecialChars(t *testing.T) {
	c := newLocalAnnotationClient("localhost")
	req, err := c.DeleteAnnotationRequest(AnnotationKindBranch, "data/my branch", "my annotation")
	require.NoError(t, err)
	assert.Equal(t, "localhost/branches/data/my%20branch/annotations/my%20annotation", req.URL.EscapedPath())
}

func TestDeleteAnnotation_NoContent(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/branches/data/my-branch/annotations/owner", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	defer ts.Close()

	assert.NoError(t, c.V2().DeleteAnnotation(AnnotationKindBranch, "data/my-branch", "owner"))
}

func TestDeleteAnnotation_NonExistentNotFound(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"annotation not found"}}`))
	})
	defer ts.Close()

	err := c.V2().DeleteAnnotation(AnnotationKindWorkload, "data/w", "missing")
	var notFoundErr *response.ConjurError
	require.ErrorAs(t, err, &notFoundErr, "deleting a non-existent annotation must surface a *response.ConjurError")
	assert.Equal(t, http.StatusNotFound, notFoundErr.Code, "deleting a non-existent annotation must be a distinguishable not-found")
}

func TestDeleteAnnotation_SelfHostedVersionGate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"1.0.0","services":{"possum":{"version":"1.0.0"}}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, err := NewClientFromJwt(Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSH,
	})
	require.NoError(t, err)

	err = client.V2().DeleteAnnotation(AnnotationKindGroup, "data/g", "owner")
	require.Error(t, err)
	assert.Contains(t, err.Error(), MinVersion)
}

func TestDeleteAnnotationRequest_SelfHostedAccountSegment(t *testing.T) {
	c := &ClientV2{Client: &Client{config: Config{
		ApplianceURL: "localhost",
		Account:      "myacct",
		Environment:  EnvironmentSH,
	}}}

	req, err := c.DeleteAnnotationRequest(AnnotationKindGroup, "data/my-group", "team")
	require.NoError(t, err)
	assert.Equal(t, "localhost/groups/myacct/data/my-group/annotations/team", req.URL.Path)
}

func TestDeleteAnnotation_WorkloadHardGatedOnSelfHosted(t *testing.T) {
	c := &ClientV2{Client: &Client{config: Config{
		ApplianceURL: "localhost",
		Account:      "myacct",
		Environment:  EnvironmentSH,
	}}}

	err := c.DeleteAnnotation(AnnotationKindWorkload, "data/w", "owner")
	var notSupported *contract.FeatureNotSupportedError
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(contract.CapabilityWorkloadV2), notSupported.FeatureName)
}

// On Self-Hosted the branch annotation path would match delete-branch, so
// nothing may be sent.
func TestDeleteAnnotation_BranchHardGatedOnSelfHosted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authn-jwt/jwt_service/myTestAccount/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockConjurToken))
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"release":"12.2.0","services":{"possum":{"version":"` + MinVersion + `"}}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, err := NewClientFromJwt(Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSH,
	})
	require.NoError(t, err)

	err = client.V2().DeleteAnnotation(AnnotationKindBranch, "data/b", "owner")
	var notSupported *contract.FeatureNotSupportedError
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(contract.CapabilityBranchAnnotationsV2), notSupported.FeatureName)
}

func newSelfHostedAnnotationClient() *ClientV2 {
	return &ClientV2{Client: &Client{config: Config{
		ApplianceURL: "localhost",
		Account:      "myacct",
		Environment:  EnvironmentSH,
	}}}
}

// newSelfHostedAnnotationServer is a Self-Hosted server at MinVersion whose
// catch-all handler fails the test, for checks that nothing is sent.
func newSelfHostedAnnotationServer(t *testing.T) (*httptest.Server, *Client) {
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)

	client, err := NewClientFromJwt(Config{
		ApplianceURL: ts.URL,
		Account:      "myTestAccount",
		AuthnType:    "jwt",
		ServiceID:    "jwt_service",
		JWTContent:   `{"protected":"true","payload":"true","signature":"yes"}`,
		Environment:  EnvironmentSH,
	})
	if err != nil {
		ts.Close()
		t.Fatalf("NewClientFromJwt: %s", err)
	}
	return ts, client
}

func decodeAnnotationsBody(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "body: %s", raw)
	return body
}

var annotationRequestCases = []struct {
	kind   AnnotationKind
	id     string
	path   string
	header string
}{
	{AnnotationKindWorkload, "data/my-workload", "localhost/workloads/data/my-workload", v2APIHeader},
	{AnnotationKindGroup, "data/my-group", "localhost/groups/data/my-group", v2APIHeaderBeta},
	{AnnotationKindBranch, "data/my-branch", "localhost/branches/data/my-branch", v2APIHeaderBeta},
}

func TestSetAnnotationRequest_PerKind(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	for _, tc := range annotationRequestCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			req, err := c.SetAnnotationRequest(tc.kind, tc.id, "owner", "alice")
			require.NoError(t, err)
			assert.Equal(t, http.MethodPatch, req.Method)
			assert.Equal(t, tc.path, req.URL.Path)
			assert.Equal(t, tc.header, req.Header.Get(v2APIOutgoingHeaderID))
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			// Only the one annotation is sent, never the whole map, so the
			// server's per-key merge leaves the others alone.
			assert.Equal(t,
				map[string]any{"annotations": map[string]any{"owner": "alice"}},
				decodeAnnotationsBody(t, req),
			)
		})
	}
}

func TestListAnnotationsRequest_PerKind(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	for _, tc := range annotationRequestCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			req, err := c.ListAnnotationsRequest(tc.kind, tc.id)
			require.NoError(t, err)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, tc.path, req.URL.Path)
			assert.Equal(t, tc.header, req.Header.Get(v2APIOutgoingHeaderID))
		})
	}
}

func TestSetAnnotationRequest_NameNeedingEscapingStaysInBody(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	for _, name := range []string{"team/owner", "a:b", "my annotation", "a/.."} {
		req, err := c.SetAnnotationRequest(AnnotationKindBranch, "data/b", name, "v")
		require.NoError(t, err)
		assert.Equal(t, "localhost/branches/data/b", req.URL.EscapedPath(), "the name must not reach the URL")
		assert.Equal(t,
			map[string]any{"annotations": map[string]any{name: "v"}},
			decodeAnnotationsBody(t, req),
		)
	}
}

func TestAnnotationResourceRequests_EscapeIdentifier(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	req, err := c.ListAnnotationsRequest(AnnotationKindBranch, "data/my branch")
	require.NoError(t, err)
	assert.Equal(t, "localhost/branches/data/my%20branch", req.URL.EscapedPath())

	req, err = c.SetAnnotationRequest(AnnotationKindWorkload, "data/a?b#c", "owner", "v")
	require.NoError(t, err)
	assert.Equal(t, "localhost/workloads/data/a%3Fb%23c", req.URL.EscapedPath())
}

// branchURL joins the identifier unescaped, so this is what keeps "data/../x"
// from addressing a different resource.
func TestAnnotationResourceRequests_RejectTraversal(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	for _, kind := range SupportedAnnotationKinds() {
		for _, bad := range []string{"data/../admin", "..", "data/./x", "data//x"} {
			_, err := c.ListAnnotationsRequest(kind, bad)
			assert.Errorf(t, err, "%s: list on identifier %q must be rejected", kind, bad)

			_, err = c.SetAnnotationRequest(kind, bad, "owner", "v")
			assert.Errorf(t, err, "%s: set on identifier %q must be rejected", kind, bad)
		}
	}
}

func TestAnnotationResourceRequests_Validation(t *testing.T) {
	c := newLocalAnnotationClient("localhost")

	_, err := c.ListAnnotationsRequest(AnnotationKind("safe"), "x")
	assert.ErrorContains(t, err, "unsupported annotation kind")

	_, err = c.SetAnnotationRequest(AnnotationKind("safe"), "x", "n", "v")
	assert.ErrorContains(t, err, "unsupported annotation kind")

	_, err = c.ListAnnotationsRequest(AnnotationKindBranch, "")
	assert.ErrorContains(t, err, "identifier")

	_, err = c.SetAnnotationRequest(AnnotationKindBranch, "data/b", "", "v")
	assert.ErrorContains(t, err, "annotation name")

	_, err = c.GetAnnotation(AnnotationKindBranch, "data/b", "")
	assert.ErrorContains(t, err, "annotation name")

	_, err = c.GetAnnotation(AnnotationKindBranch, "data/b", "..")
	assert.ErrorContains(t, err, `Annotation name must not be ".."`)

	// What the server refuses to set is refused before sending.
	refused := []struct {
		kind  AnnotationKind
		name  string
		value string
		want  string
	}{
		{AnnotationKindGroup, "owner", "", "Must specify an annotation value; to remove an annotation, delete it"},
		{AnnotationKindGroup, "owner", " \t\n", "Annotation value must not be only whitespace"},
		{AnnotationKindGroup, "   ", "v", "Annotation name must not be only whitespace"},
		{AnnotationKindGroup, ".", "v", `Annotation name must not be "."`},
		{AnnotationKindGroup, "..", "v", `Annotation name must not be ".."`},
		{AnnotationKindGroup, "a/../b", "v", `Annotation name must not contain "../"`},
		{AnnotationKindGroup, `a..\b`, "v", `Annotation name must not contain "../"`},
		{AnnotationKindGroup, strings.Repeat("ü", 129), "v", "Annotation name is 129 characters, more than the limit of 128"},
		{AnnotationKindGroup, "owner", strings.Repeat("ü", 513), "Annotation value is 513 characters, more than the limit of 512"},
		{AnnotationKindGroup, "a<b", "v", "Annotation name must not contain <, > or '"},
		{AnnotationKindGroup, "a>b", "v", "Annotation name must not contain <, > or '"},
		{AnnotationKindGroup, "a'b", "v", "Annotation name must not contain <, > or '"},
		{AnnotationKindGroup, "owner", "ok\n<b>x</b>", "Annotation value must not contain <, > or '"},
		{AnnotationKindWorkload, "type", "v", `Annotation name "type" is reserved on workloads`},
		{AnnotationKindWorkload, "authn/api-key", "v", "reserved on workloads"},
		{AnnotationKindWorkload, "authn-jwt/prod", "v", "reserved on workloads"},
		{AnnotationKindWorkload, "authn-iam/prod", "v", "reserved on workloads"},
		{AnnotationKindWorkload, "authn-gcp/x", "v", "reserved on workloads"},
		{AnnotationKindWorkload, "authn-azure/prod/sub", "v", "reserved on workloads"},
		{AnnotationKindWorkload, "authn-cert/san-dns", "v", "reserved on workloads"},
	}
	for _, tc := range refused {
		_, err := c.SetAnnotationRequest(tc.kind, "data/x", tc.name, tc.value)
		assert.ErrorContains(t, err, tc.want, "%s %q=%q", tc.kind, tc.name, tc.value)
	}

	// Every problem is reported at once.
	_, err = c.SetAnnotationRequest(AnnotationKindWorkload, "data/x", "type", "")
	assert.ErrorContains(t, err, "reserved on workloads")
	assert.ErrorContains(t, err, "Must specify an annotation value")

	_, err = c.SetAnnotationRequest(AnnotationKindGroup, "data/x", "a/../<b>", "")
	assert.ErrorContains(t, err, `Annotation name must not contain "../"`)
	assert.ErrorContains(t, err, "Annotation name must not contain <, > or '")
	assert.ErrorContains(t, err, "Must specify an annotation value")

	// The checks stop at the server's rules, not short of them.
	allowed := []struct {
		kind  AnnotationKind
		name  string
		value string
	}{
		{AnnotationKindGroup, strings.Repeat("ü", 128), strings.Repeat("ü", 512)},
		{AnnotationKindGroup, "type", "v"},
		{AnnotationKindBranch, "authn-jwt/prod", "v"},
		{AnnotationKindWorkload, "TYPE", "v"},
		{AnnotationKindWorkload, "authn-jwt", "v"},
		{AnnotationKindWorkload, "authn-jwt/", "v"},
		{AnnotationKindWorkload, "authn-foo/x", "v"},
		{AnnotationKindGroup, "...", "v"},
		{AnnotationKindGroup, "a/..", "v"},
		{AnnotationKindGroup, `a"b&c\d;e=f,g@h`, "  padded  "},
	}
	for _, tc := range allowed {
		_, err := c.SetAnnotationRequest(tc.kind, "data/x", tc.name, tc.value)
		assert.NoError(t, err, "%s %q=%q", tc.kind, tc.name, tc.value)
	}
}

func TestAnnotationResourceRequests_SelfHostedAccountSegment(t *testing.T) {
	c := newSelfHostedAnnotationClient()

	req, err := c.ListAnnotationsRequest(AnnotationKindGroup, "data/my-group")
	require.NoError(t, err)
	assert.Equal(t, "localhost/groups/myacct/data/my-group", req.URL.Path)

	req, err = c.SetAnnotationRequest(AnnotationKindGroup, "data/my-group", "owner", "v")
	require.NoError(t, err)
	assert.Equal(t, "localhost/groups/myacct/data/my-group", req.URL.Path)
}

func TestListAnnotations(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/groups/data/my-group", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"my-group","branch":"data","annotations":{"team":"ops","env":"prod"}}`))
	})
	defer ts.Close()

	annotations, err := c.V2().ListAnnotations(AnnotationKindGroup, "data/my-group")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"team": "ops", "env": "prod"}, annotations)
}

func TestListAnnotations_NoneGivesEmptyMap(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"b","branch":"data"}`))
	})
	defer ts.Close()

	annotations, err := c.V2().ListAnnotations(AnnotationKindBranch, "data/b")
	require.NoError(t, err)
	assert.NotNil(t, annotations)
	assert.Empty(t, annotations)
}

func TestListAnnotations_MissingResourceNotFound(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"Workload 'data/w' not found"}}`))
	})
	defer ts.Close()

	_, err := c.V2().ListAnnotations(AnnotationKindWorkload, "data/w")
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	assert.Equal(t, http.StatusNotFound, conjurErr.Code)
}

func TestGetAnnotation(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/workloads/data/w", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"w","branch":"data","annotations":{"owner":"alice","empty":""}}`))
	})
	defer ts.Close()

	value, err := c.V2().GetAnnotation(AnnotationKindWorkload, "data/w", "owner")
	require.NoError(t, err)
	assert.Equal(t, "alice", value)

	// An annotation with an empty value exists; it is not "not found".
	value, err = c.V2().GetAnnotation(AnnotationKindWorkload, "data/w", "empty")
	require.NoError(t, err)
	assert.Equal(t, "", value)
}

func TestGetAnnotation_MissingAnnotationNotFound(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"b","branch":"data","annotations":{"owner":"alice"}}`))
	})
	defer ts.Close()

	_, err := c.V2().GetAnnotation(AnnotationKindBranch, "data/b", "missing")
	var notFoundErr *response.ConjurError
	require.ErrorAs(t, err, &notFoundErr, "a missing annotation must be the same not-found as DeleteAnnotation's")
	assert.Equal(t, http.StatusNotFound, notFoundErr.Code)
	assert.EqualError(t, err, "404 Not Found. Annotation 'missing' not found on branch 'data/b'.")
}

func TestSupportedAnnotationKindNames(t *testing.T) {
	assert.Equal(t, []string{"branch", "group", "workload"}, SupportedAnnotationKindNames())
}

func TestSetAnnotation(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/branches/data/my-branch", r.URL.Path)
		assert.Equal(t,
			map[string]any{"annotations": map[string]any{"owner": "alice"}},
			decodeAnnotationsBody(t, r),
		)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"my-branch","branch":"data","annotations":{"owner":"alice","env":"prod"}}`))
	})
	defer ts.Close()

	assert.NoError(t, c.V2().SetAnnotation(AnnotationKindBranch, "data/my-branch", "owner", "alice"))
}

// The 422 for a 21st annotation, which only the server can check, must reach
// the caller unchanged.
func TestSetAnnotation_ServerRejectionPassedThrough(t *testing.T) {
	ts, c := newSaaSAnnotationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":{"code":"unprocessable_entity","message":"Cannot have more than 20 annotations"}}`))
	})
	defer ts.Close()

	err := c.V2().SetAnnotation(AnnotationKindWorkload, "data/w", "k21", "v")
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
	assert.Contains(t, conjurErr.Error(), "Cannot have more than 20 annotations")
}

// Branch annotations are SaaS-only for every operation and request builder, not
// only delete, so a branch annotation cannot be set where it cannot be removed.
func TestAnnotationWrappers_BranchHardGatedOnSelfHosted(t *testing.T) {
	ts, client := newSelfHostedAnnotationServer(t)
	defer ts.Close()
	c := client.V2()

	calls := map[string]func() error{
		"set":  func() error { return c.SetAnnotation(AnnotationKindBranch, "data/b", "owner", "v") },
		"list": func() error { _, err := c.ListAnnotations(AnnotationKindBranch, "data/b"); return err },
		"get":  func() error { _, err := c.GetAnnotation(AnnotationKindBranch, "data/b", "owner"); return err },
		"set request": func() error {
			_, err := c.SetAnnotationRequest(AnnotationKindBranch, "data/b", "owner", "v")
			return err
		},
		"list request": func() error {
			_, err := c.ListAnnotationsRequest(AnnotationKindBranch, "data/b")
			return err
		},
		"delete request": func() error {
			_, err := c.DeleteAnnotationRequest(AnnotationKindBranch, "data/b", "owner")
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var notSupported *contract.FeatureNotSupportedError
			require.ErrorAs(t, call(), &notSupported)
			assert.Equal(t, string(contract.CapabilityBranchAnnotationsV2), notSupported.FeatureName)
		})
	}
}

func TestAnnotationWrappers_WorkloadHardGatedOnSelfHosted(t *testing.T) {
	c := newSelfHostedAnnotationClient()

	err := c.SetAnnotation(AnnotationKindWorkload, "data/w", "owner", "v")
	var notSupported *contract.FeatureNotSupportedError
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(contract.CapabilityWorkloadV2), notSupported.FeatureName)

	_, err = c.ListAnnotations(AnnotationKindWorkload, "data/w")
	require.ErrorAs(t, err, &notSupported)
}

func TestAnnotations_ValidationErrorWithDetailsList(t *testing.T) {
	ts, client := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(validationFailedBody))
	})
	defer ts.Close()
	c := client.V2()
	want := "422 Unprocessable Entity. value is not present."

	err := c.SetAnnotation(AnnotationKindGroup, "data/g", "space", "v")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	err = c.DeleteAnnotation(AnnotationKindGroup, "data/g", "space")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())
}
