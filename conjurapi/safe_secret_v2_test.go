package conjurapi

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const safeSecretTestBaseURL = "http://conjur.test"

const testSafeName = "my-safe"

type safeSecretRequestBuilder struct {
	name            string
	fixedSafeType   string
	takesSecretName bool
	contentType     string
	build           func(safeType, safeName, secretName string) (*http.Request, error)
}

func safeSecretRequestBuilders(c *ClientV2) []safeSecretRequestBuilder {
	return []safeSecretRequestBuilder{
		{"CreateManagedSafeSecretRequest", "managed", false, "application/json", func(_, safeName, _ string) (*http.Request, error) {
			return c.CreateManagedSecretRequest(safeName, ManagedSecretCreate{Name: "my-secret", Value: "v"})
		}},
		{"CreateDynamicSafeSecretRequest", "dynamic", false, "application/json", func(_, safeName, _ string) (*http.Request, error) {
			return c.CreateDynamicSecretRequest(safeName, DynamicSecretCreate{Name: "my-secret", Issuer: "issuer", Method: "assume-role"})
		}},
		{"ListSafeSecretsRequest", "", false, "", func(safeType, safeName, _ string) (*http.Request, error) {
			return c.ListSecretsRequest(safeType, safeName, ListSafeSecretParams{})
		}},
		{"GetSafeSecretMetadataRequest", "", true, "", func(safeType, safeName, secretName string) (*http.Request, error) {
			return c.GetSecretMetadataRequest(safeType, safeName, secretName)
		}},
		{"GetSafeSecretValueRequest", "", true, "", func(safeType, safeName, secretName string) (*http.Request, error) {
			return c.GetSecretValueRequest(safeType, safeName, secretName, 0)
		}},
		{"SetManagedSafeSecretValueRequest", "managed", true, "application/octet-stream", func(_, safeName, secretName string) (*http.Request, error) {
			return c.SetManagedSecretValueRequest(safeName, secretName, []byte("v"), "application/octet-stream")
		}},
		{"UpdateManagedSafeSecretRequest/partial", "managed", true, "application/json", func(_, safeName, secretName string) (*http.Request, error) {
			return c.UpdateManagedSecretRequest(safeName, secretName, ManagedSecretUpdate{Value: "v"}, true)
		}},
		{"UpdateManagedSafeSecretRequest/full", "managed", true, "application/json", func(_, safeName, secretName string) (*http.Request, error) {
			return c.UpdateManagedSecretRequest(safeName, secretName, ManagedSecretUpdate{Value: "v"}, false)
		}},
		{"UpdateDynamicSafeSecretRequest", "dynamic", true, "application/json", func(_, safeName, secretName string) (*http.Request, error) {
			return c.UpdateDynamicSecretRequest(safeName, secretName, DynamicSecretUpdate{Issuer: "issuer", Method: "assume-role"}, false)
		}},
		{"DeleteSafeSecretRequest", "", true, "", func(safeType, safeName, secretName string) (*http.Request, error) {
			return c.DeleteSafeSecretRequest(safeType, safeName, secretName)
		}},
	}
}

func readSafeSecretRequestBody(t *testing.T, req *http.Request) string {
	t.Helper()
	require.NotNil(t, req.Body)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return string(body)
}

func TestSafeSecretsURL_RequiresSafeTypeAndName(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	_, err := c.secretsURL("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify a Safe type")
	assert.Contains(t, err.Error(), "Must specify a Safe name")

	_, err = c.secretsURL("", testSafeName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify a Safe type")
	assert.NotContains(t, err.Error(), "Must specify a Safe name")

	_, err = c.secretsURL("managed", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify a Safe name")
	assert.NotContains(t, err.Error(), "Must specify a Safe type")

	_, err = c.secretsURL("managed", testSafeName)
	assert.NoError(t, err)
}

func TestSafeSecretRequests_RejectInvalidSegments(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	invalidSegments := []string{"", ".", ".."}

	for _, b := range safeSecretRequestBuilders(c) {
		t.Run(b.name, func(t *testing.T) {
			_, err := b.build("managed", testSafeName, "my-secret")
			require.NoError(t, err, "valid inputs must build")

			for _, safeName := range append(invalidSegments, "data/../admin", "data/./x", "data//x") {
				_, err := b.build("managed", safeName, "my-secret")
				assert.Error(t, err, "safeName %q", safeName)
			}

			if b.fixedSafeType == "" {
				for _, safeType := range invalidSegments {
					_, err := b.build(safeType, testSafeName, "my-secret")
					assert.Error(t, err, "safeType %q", safeType)
				}
			}

			if !b.takesSecretName {
				return
			}
			for _, secretName := range invalidSegments {
				_, err := b.build("managed", testSafeName, secretName)
				if assert.Error(t, err, "secretName %q", secretName) {
					assert.Contains(t, err.Error(), "Safe Secret(s) URL")
				}
			}
		})
	}
}

func TestSafeSecretRequests_EscapeSpecialCharacters(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	for _, b := range safeSecretRequestBuilders(c) {
		t.Run(b.name, func(t *testing.T) {
			safeType := "managed"
			if b.fixedSafeType != "" {
				safeType = b.fixedSafeType
			}
			req, err := b.build(safeType, "my/safe", "a b?#")
			require.NoError(t, err)

			want := "/safes/" + safeType + "/my%2Fsafe/secrets"
			if b.takesSecretName {
				want += "/a%20b%3F%23"
			}
			if strings.HasSuffix(b.name, "SecretValueRequest") {
				want += "/value"
			}
			assert.True(t, strings.HasSuffix(req.URL.EscapedPath(), want), "escaped path %q does not end with %q", req.URL.EscapedPath(), want)
			assert.Empty(t, req.URL.RawQuery)
			assert.Empty(t, req.URL.Fragment)
		})
	}
}

func TestSafeSecretRequests_Headers(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	for _, b := range safeSecretRequestBuilders(c) {
		t.Run(b.name, func(t *testing.T) {
			req, err := b.build("managed", testSafeName, "my-secret")
			require.NoError(t, err)

			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
			if b.contentType != "" {
				assert.Equal(t, b.contentType, req.Header.Get("Content-Type"))
				assert.NotNil(t, req.Body)
			} else {
				assert.Empty(t, req.Header.Get("Content-Type"))
				assert.True(t, req.Body == nil || req.Body == http.NoBody, "expected no body")
			}
		})
	}
}

func TestClientV2_CreateManagedSafeSecretRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Name: "my-secret", Value: "s3cr3t", MimeType: "text/plain", Annotations: map[string]string{"team": "coco"}})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets", req.URL.Path)
	assert.JSONEq(t, `{"name":"my-secret","value":"s3cr3t","mime_type":"text/plain","annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	req, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Name: "my-secret", Value: "s3cr3t"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"my-secret","value":"s3cr3t"}`, readSafeSecretRequestBody(t, req))

	_, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify secret name")
	assert.Contains(t, err.Error(), "must specify secret value")

	_, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Value: "s3cr3t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify secret name")
	assert.NotContains(t, err.Error(), "must specify secret value")

	_, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Name: "my-secret"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify secret value")
	assert.NotContains(t, err.Error(), "must specify secret name")
	assert.NotContains(t, err.Error(), "secret value must be valid UTF-8")

	req, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Name: "my-secret", Value: "a\xffb"})
	assert.ErrorContains(t, err, "secret value must be valid UTF-8")
	assert.Nil(t, req)

	req, err = c.CreateManagedSecretRequest(testSafeName, ManagedSecretCreate{Name: "my-secret", Value: "päss"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"my-secret","value":"päss"}`, readSafeSecretRequestBody(t, req))
}

func TestClientV2_CreateDynamicSafeSecretRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.CreateDynamicSecretRequest(testSafeName, DynamicSecretCreate{
		Name:         "my-secret",
		Issuer:       "aws-issuer",
		TTL:          3600,
		Method:       "assume-role",
		MethodParams: map[string]any{"role_arn": "arn:aws:iam::123456789012:role/r", "region": "us-east-1", "inline_policy": `{"Version":"2012-10-17"}`},
		Annotations:  map[string]string{"team": "coco"},
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "/safes/dynamic/my-safe/secrets", req.URL.Path)
	assert.JSONEq(t, `{"name":"my-secret","issuer":"aws-issuer","ttl":3600,"method":"assume-role","method_params":{"role_arn":"arn:aws:iam::123456789012:role/r","region":"us-east-1","inline_policy":"{\"Version\":\"2012-10-17\"}"},"annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	req, err = c.CreateDynamicSecretRequest(testSafeName, DynamicSecretCreate{Name: "my-secret", Issuer: "aws-issuer", Method: "assume-role"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"my-secret","issuer":"aws-issuer","method":"assume-role"}`, readSafeSecretRequestBody(t, req))

	_, err = c.CreateDynamicSecretRequest(testSafeName, DynamicSecretCreate{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify secret name")
	assert.Contains(t, err.Error(), "must specify issuer")
	assert.Contains(t, err.Error(), "must specify method")
}

func TestClientV2_ListSafeSecretsRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets", req.URL.EscapedPath())
	assert.Empty(t, req.URL.RawQuery)
	assert.NotContains(t, req.URL.String(), "?")

	req, err = c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{Limit: 10, Offset: 20, Filter: "a b"})
	require.NoError(t, err)
	assert.Equal(t, "/safes/managed/my-safe/secrets", req.URL.EscapedPath())
	query := req.URL.Query()
	assert.Equal(t, "10", query.Get("limit"))
	assert.Equal(t, "20", query.Get("offset"))
	assert.Equal(t, "a b", query.Get("filter"))
	assert.Len(t, query, 3)

	req, err = c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{Filter: "a&b=c d?#"})
	require.NoError(t, err)
	assert.Equal(t, "/safes/managed/my-safe/secrets", req.URL.EscapedPath())
	query = req.URL.Query()
	assert.Equal(t, "a&b=c d?#", query.Get("filter"))
	assert.Len(t, query, 1)
	assert.Empty(t, req.URL.Fragment)

	req, err = c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{Limit: 5})
	require.NoError(t, err)
	query = req.URL.Query()
	assert.Equal(t, "5", query.Get("limit"))
	assert.Len(t, query, 1)

	req, err = c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{Limit: -1, Offset: -5})
	require.NoError(t, err)
	assert.Empty(t, req.URL.RawQuery)
	assert.NotContains(t, req.URL.String(), "?")
}

func TestClientV2_GetSafeSecretMetadataRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.GetSecretMetadataRequest("managed", testSafeName, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret", req.URL.Path)
	assert.Empty(t, req.URL.RawQuery)
}

func TestClientV2_GetSafeSecretValueRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	for _, version := range []int{0, -1} {
		req, err := c.GetSecretValueRequest("managed", testSafeName, "my-secret", version)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret/value", req.URL.EscapedPath())
		assert.Empty(t, req.URL.RawQuery, "version %d", version)
		assert.NotContains(t, req.URL.String(), "?", "version %d", version)
	}

	req, err := c.GetSecretValueRequest("managed", testSafeName, "my-secret", 3)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret/value", req.URL.EscapedPath())
	query := req.URL.Query()
	assert.Equal(t, "3", query.Get("version"))
	assert.Len(t, query, 1)

	req, err = c.GetSecretValueRequest("managed", "my/safe", "a b?#", 2)
	require.NoError(t, err)
	assert.Equal(t, "/safes/managed/my%2Fsafe/secrets/a%20b%3F%23/value", req.URL.EscapedPath())
	assert.Equal(t, "2", req.URL.Query().Get("version"))
	assert.Empty(t, req.URL.Fragment)
}

func TestClientV2_UpdateManagedSafeSecretRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)
	update := ManagedSecretUpdate{Value: "s3cr3t", MimeType: "text/plain", Annotations: map[string]string{"team": "coco"}}

	req, err := c.UpdateManagedSecretRequest(testSafeName, "my-secret", update, true)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPatch, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret", req.URL.Path)
	assert.JSONEq(t, `{"value":"s3cr3t","mime_type":"text/plain","annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", update, false)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret", req.URL.Path)
	assert.JSONEq(t, `{"value":"s3cr3t","mime_type":"text/plain","annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", ManagedSecretUpdate{Annotations: map[string]string{"team": "coco"}}, true)
	require.NoError(t, err)
	assert.JSONEq(t, `{"annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", ManagedSecretUpdate{}, false)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, readSafeSecretRequestBody(t, req))

	for _, partial := range []bool{true, false} {
		req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", ManagedSecretUpdate{Value: "a\xffb"}, partial)
		assert.ErrorContains(t, err, "secret value must be valid UTF-8", "partial %t", partial)
		assert.Nil(t, req, "partial %t", partial)

		req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", ManagedSecretUpdate{MimeType: "text/plain"}, partial)
		require.NoError(t, err, "partial %t", partial)
		assert.JSONEq(t, `{"mime_type":"text/plain"}`, readSafeSecretRequestBody(t, req))

		req, err = c.UpdateManagedSecretRequest(testSafeName, "my-secret", ManagedSecretUpdate{Value: "päss"}, partial)
		require.NoError(t, err, "partial %t", partial)
		assert.JSONEq(t, `{"value":"päss"}`, readSafeSecretRequestBody(t, req))
	}
}

func TestManagedSafeSecretUpdate_Validate(t *testing.T) {
	assert.NoError(t, ManagedSecretUpdate{}.Validate())
	assert.NoError(t, ManagedSecretUpdate{Value: "s3cr3t"}.Validate())
	assert.NoError(t, ManagedSecretUpdate{Value: "päss"}.Validate())
	assert.ErrorContains(t, ManagedSecretUpdate{Value: "a\xffb"}.Validate(), "secret value must be valid UTF-8")
}

func TestClientV2_SetManagedSafeSecretValueRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)
	binaryValue := []byte{0x20, 0x20, 0x61, 0xFF, 0xFE, 0x80, 0xC3, 0x62, 0xE2, 0x82, 0x63, 0xC0, 0xAF, 0xED, 0xA0, 0x80, 0xF4, 0x90, 0x80, 0x80, 0x64, 0x20, 0x20, 0x0A}

	cases := []struct {
		name     string
		safeName string
		value    []byte
		mimeType string
		wantErrs []string
	}{
		{"binary value", testSafeName, binaryValue, "application/octet-stream", nil},
		{"text value", testSafeName, []byte("s3cr3t value\n"), "text/plain", nil},
		{"empty value", testSafeName, []byte{}, "text/plain", []string{"must specify secret value"}},
		{"nil value", testSafeName, nil, "text/plain", []string{"must specify secret value"}},
		{"blank MIME type", testSafeName, binaryValue, "", []string{"invalid MIME type"}},
		{"whitespace MIME type", testSafeName, binaryValue, " ", []string{"invalid MIME type"}},
		{"JSON MIME type with raw value", testSafeName, binaryValue, "application/json", nil},
		{"malformed MIME type", testSafeName, binaryValue, "text/plain; charset", []string{"invalid MIME type"}},
		{"empty safe name", "", binaryValue, "text/plain", []string{"Must specify a Safe name"}},
		{"empty value and MIME type", testSafeName, nil, "", []string{"must specify secret value", "invalid MIME type"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := c.SetManagedSecretValueRequest(tc.safeName, "my-secret", tc.value, tc.mimeType)
			if len(tc.wantErrs) > 0 {
				for _, wantErr := range tc.wantErrs {
					assert.ErrorContains(t, err, wantErr)
				}
				assert.Nil(t, req)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, http.MethodPut, req.Method)
			assert.Equal(t, safeSecretTestBaseURL+"/safes/managed/my-safe/secrets/my-secret/value", req.URL.String())
			assert.Equal(t, tc.mimeType, req.Header.Get("Content-Type"))
			assert.Equal(t, v2APIHeaderBeta, req.Header.Get(v2APIOutgoingHeaderID))
			require.NotNil(t, req.Body)
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.value, body)
		})
	}
}

func TestClientV2_UpdateDynamicSafeSecretRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.UpdateDynamicSecretRequest(testSafeName, "my-secret", DynamicSecretUpdate{Annotations: map[string]string{"team": "coco"}}, true)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPatch, req.Method)
	assert.Equal(t, "/safes/dynamic/my-safe/secrets/my-secret", req.URL.Path)
	assert.JSONEq(t, `{"annotations":{"team":"coco"}}`, readSafeSecretRequestBody(t, req))

	_, err = c.UpdateDynamicSecretRequest(testSafeName, "my-secret", DynamicSecretUpdate{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify issuer")
	assert.Contains(t, err.Error(), "must specify method")

	req, err = c.UpdateDynamicSecretRequest(testSafeName, "my-secret", DynamicSecretUpdate{Issuer: "aws-issuer", TTL: 900, Method: "assume-role", MethodParams: map[string]any{"role_arn": "arn:aws:iam::123456789012:role/r", "region": "eu-west-1"}}, false)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, req.Method)
	assert.Equal(t, "/safes/dynamic/my-safe/secrets/my-secret", req.URL.Path)
	assert.JSONEq(t, `{"issuer":"aws-issuer","ttl":900,"method":"assume-role","method_params":{"role_arn":"arn:aws:iam::123456789012:role/r","region":"eu-west-1"}}`, readSafeSecretRequestBody(t, req))
}

func TestDynamicSafeSecretUpdate_ValidateReplace(t *testing.T) {
	assert.NoError(t, DynamicSecretUpdate{Issuer: "issuer", Method: "assume-role"}.ValidateReplace())
	assert.ErrorContains(t, DynamicSecretUpdate{Method: "assume-role"}.ValidateReplace(), "must specify issuer")
	assert.ErrorContains(t, DynamicSecretUpdate{Issuer: "issuer"}.ValidateReplace(), "must specify method")
}

func TestClientV2_DeleteSafeSecretRequest(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	req, err := c.DeleteSafeSecretRequest("managed", testSafeName, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, req.Method)
	assert.Equal(t, "/safes/managed/my-safe/secrets/my-secret", req.URL.Path)
}

func TestClientV2_SafeSecretURLs(t *testing.T) {
	c := newLocalGroupClient(safeSecretTestBaseURL)

	got, err := c.secretsURL("managed", testSafeName)
	require.NoError(t, err)
	assert.Equal(t, "http", got.Scheme)
	assert.Equal(t, "conjur.test", got.Host)
	assert.Equal(t, "http://conjur.test/safes/managed/my-safe/secrets", got.String())
	assert.Empty(t, got.RawQuery)

	got, err = c.secretURL("managed", testSafeName, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, "http://conjur.test/safes/managed/my-safe/secrets/my-secret", got.String())

	got, err = c.secretValueURL("managed", testSafeName, "my-secret")
	require.NoError(t, err)
	assert.Equal(t, "http://conjur.test/safes/managed/my-safe/secrets/my-secret/value", got.String())

	got, err = c.secretURL("managed", "my/safe", "a b?#")
	require.NoError(t, err)
	assert.Equal(t, "conjur.test", got.Host)
	assert.Equal(t, "/safes/managed/my%2Fsafe/secrets/a%20b%3F%23", got.EscapedPath())
	assert.Equal(t, "http://conjur.test/safes/managed/my%2Fsafe/secrets/a%20b%3F%23", got.String())
	assert.Empty(t, got.RawQuery)
	assert.Empty(t, got.Fragment)

	got, err = c.secretValueURL("managed", "my/safe", "a b?#")
	require.NoError(t, err)
	assert.Equal(t, "/safes/managed/my%2Fsafe/secrets/a%20b%3F%23/value", got.EscapedPath())

	got, err = c.secretsURL("", "")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestClientV2_SafeSecretURLs_InvalidApplianceURL(t *testing.T) {
	c := newLocalGroupClient("http://conjur.test/\x7f")

	got, err := c.secretsURL("managed", testSafeName)
	assert.Error(t, err)
	assert.Nil(t, got)

	got, err = c.secretURL("managed", testSafeName, "my-secret")
	assert.Error(t, err)
	assert.Nil(t, got)

	got, err = c.secretValueURL("managed", testSafeName, "my-secret")
	assert.Error(t, err)
	assert.Nil(t, got)

	for _, b := range safeSecretRequestBuilders(c) {
		t.Run(b.name, func(t *testing.T) {
			req, err := b.build("managed", testSafeName, "my-secret")
			assert.Error(t, err)
			assert.Nil(t, req)
		})
	}

	req, err := c.ListSecretsRequest("managed", testSafeName, ListSafeSecretParams{Limit: 10, Filter: "a b"})
	assert.Error(t, err)
	assert.Nil(t, req)

	req, err = c.GetSecretValueRequest("managed", testSafeName, "my-secret", 3)
	assert.Error(t, err)
	assert.Nil(t, req)
}

type safeSecretCapturedRequest struct {
	calls       int
	method      string
	path        string
	rawQuery    string
	accept      string
	contentType string
	body        string
}

func newSafeSecretMockServer(t *testing.T, status int, contentType string, body []byte) (*ClientV2, *safeSecretCapturedRequest) {
	t.Helper()
	captured := &safeSecretCapturedRequest{}
	c := newAuthenticatedMockServer(t, EnvironmentSaaS, func(w http.ResponseWriter, r *http.Request) {
		reqBody, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		captured.calls++
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.rawQuery = r.URL.RawQuery
		captured.accept = r.Header.Get(v2APIOutgoingHeaderID)
		captured.contentType = r.Header.Get("Content-Type")
		captured.body = string(reqBody)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		w.Write(body)
	})
	return c.V2(), captured
}

type safeSecretWrapper struct {
	name  string
	typed bool
	call  func(safeName string) (any, error)
}

func safeSecretWrappers(c *ClientV2) []safeSecretWrapper {
	return []safeSecretWrapper{
		{"CreateManagedSafeSecret", true, func(safeName string) (any, error) {
			return c.CreateManagedSecret(safeName, ManagedSecretCreate{Name: "my-secret", Value: "v"})
		}},
		{"CreateDynamicSafeSecret", true, func(safeName string) (any, error) {
			return c.CreateDynamicSecret(safeName, DynamicSecretCreate{Name: "my-secret", Issuer: "issuer", Method: "federation-token"})
		}},
		{"ListManagedSafeSecrets", true, func(safeName string) (any, error) { return c.ListManagedSecrets(safeName, ListSafeSecretParams{}) }},
		{"ListDynamicSafeSecrets", true, func(safeName string) (any, error) { return c.ListDynamicSecrets(safeName, ListSafeSecretParams{}) }},
		{"GetManagedSafeSecretMetadata", true, func(safeName string) (any, error) { return c.GetManagedSecretMetadata(safeName, "my-secret") }},
		{"GetDynamicSafeSecretMetadata", true, func(safeName string) (any, error) { return c.GetDynamicSecretMetadata(safeName, "my-secret") }},
		{"GetManagedSafeSecretValue", false, func(safeName string) (any, error) { return c.GetManagedSecretValue(safeName, "my-secret", 0) }},
		{"SetManagedSafeSecretValue", true, func(safeName string) (any, error) {
			return c.SetManagedSecretValue(safeName, "my-secret", []byte("v"), "application/octet-stream")
		}},
		{"GetDynamicSafeSecretValue", true, func(safeName string) (any, error) { return c.GetDynamicSecretValue(safeName, "my-secret") }},
		{"PatchManagedSafeSecret", true, func(safeName string) (any, error) {
			return c.PatchManagedSecret(safeName, "my-secret", ManagedSecretUpdate{Value: "v"})
		}},
		{"PatchDynamicSafeSecret", true, func(safeName string) (any, error) {
			return c.PatchDynamicSecret(safeName, "my-secret", DynamicSecretUpdate{TTL: 900})
		}},
		{"ReplaceManagedSafeSecret", true, func(safeName string) (any, error) {
			return c.ReplaceManagedSecret(safeName, "my-secret", ManagedSecretUpdate{Value: "v"})
		}},
		{"ReplaceDynamicSafeSecret", true, func(safeName string) (any, error) {
			return c.ReplaceDynamicSecret(safeName, "my-secret", DynamicSecretUpdate{Issuer: "issuer", Method: "federation-token"})
		}},
		{"DeleteSafeSecret", false, func(safeName string) (any, error) { return nil, c.DeleteSecret("managed", safeName, "my-secret") }},
	}
}

func TestSafeSecretWrappers_TypedResponses(t *testing.T) {
	managedSafeName := "test_safe"
	dynamicSafeName := "test_dynamic_safe"

	managedSecretJSON := `{"name":"aws-secret-access-key","annotations":{"team":"coco"},"mime_type":"text/plain","created_at":"2026-10-02T13:50:10.348+00:00","version":3,"last_updated":"2026-10-02T13:50:10.348+00:00","replicated":false,"safe":{"type":"managed","name":"test_safe","replicated":false}}`
	dynamicSecretJSON := `{"name":"dyn2","annotations":{"team":"coco"},"dynamic_params":{"issuer":"test-issuer-aws","issuer_type":"aws","method":"federation-token","ttl":900,"method_params":{}},"created_at":"2026-10-05T09:31:43.849+00:00","replicated":false,"safe":{"type":"dynamic","name":"test_dynamic_safe","replicated":false}}`
	managedListJSON := `{"secrets":[{"name":"aws-secret-access-key","annotations":{},"mime_type":"text/plain","created_at":"2026-10-02T13:50:10.348+00:00","version":3,"last_updated":"2026-10-02T13:50:10.348+00:00","safe":{"type":"managed","name":"test_safe","replicated":false}}],"count":1}`
	dynamicListJSON := `{"secrets":[{"name":"dyn2","annotations":{},"dynamic_params":{"issuer":"test-issuer-aws","issuer_type":"aws","method":"federation-token","ttl":900,"method_params":{}},"created_at":"2026-10-05T09:31:43.849+00:00","safe":{"type":"dynamic","name":"test_dynamic_safe","replicated":false}}],"count":1}`
	wantDynamicParams := DynamicParams{Issuer: "test-issuer-aws", IssuerType: "aws", Method: "federation-token", TTL: new(900), MethodParams: map[string]any{}}

	assertManagedSecret := func(t *testing.T, got any) {
		secret, ok := got.(*ManagedSecret)
		require.True(t, ok, "got %T", got)
		require.NotNil(t, secret)
		assert.Equal(t, "aws-secret-access-key", secret.Name)
		assert.Equal(t, map[string]string{"team": "coco"}, secret.Annotations)
		assert.Equal(t, "text/plain", secret.MimeType)
		assert.Equal(t, "2026-10-02T13:50:10.348+00:00", secret.CreatedAt)
		assert.Equal(t, 3, secret.Version)
		assert.Equal(t, "2026-10-02T13:50:10.348+00:00", secret.LastUpdated)
		require.NotNil(t, secret.Replicated)
		assert.False(t, *secret.Replicated)
		assert.Equal(t, &SafeDetails{Type: "managed", Name: "test_safe", Replicated: false}, secret.Safe)
	}
	assertDynamicSecret := func(t *testing.T, got any) {
		secret, ok := got.(*DynamicSecret)
		require.True(t, ok, "got %T", got)
		require.NotNil(t, secret)
		assert.Equal(t, "dyn2", secret.Name)
		assert.Equal(t, map[string]string{"team": "coco"}, secret.Annotations)
		assert.Equal(t, wantDynamicParams, secret.DynamicParams)
		assert.Equal(t, "2026-10-05T09:31:43.849+00:00", secret.CreatedAt)
		require.NotNil(t, secret.Replicated)
		assert.False(t, *secret.Replicated)
		assert.Equal(t, &SafeDetails{Type: "dynamic", Name: "test_dynamic_safe", Replicated: false}, secret.Safe)
	}
	listParams := ListSafeSecretParams{Limit: 10, Offset: 5, Filter: "aws key"}

	cases := []struct {
		name       string
		status     int
		respBody   string
		wantMethod string
		wantPath   string
		wantQuery  string
		wantBody   string
		call       func(c *ClientV2) (any, error)
		check      func(t *testing.T, got any)
	}{
		{"CreateManagedSafeSecret", http.StatusCreated, managedSecretJSON, http.MethodPost, "/safes/managed/test_safe/secrets", "", `{"name":"aws-secret-access-key","value":"s3cr3t","mime_type":"text/plain","annotations":{"team":"coco"}}`, func(c *ClientV2) (any, error) {
			return c.CreateManagedSecret(managedSafeName, ManagedSecretCreate{Name: "aws-secret-access-key", Value: "s3cr3t", MimeType: "text/plain", Annotations: map[string]string{"team": "coco"}})
		}, assertManagedSecret},
		{"CreateDynamicSafeSecret", http.StatusCreated, dynamicSecretJSON, http.MethodPost, "/safes/dynamic/test_dynamic_safe/secrets", "", `{"name":"dyn2","issuer":"test-issuer-aws","ttl":900,"method":"federation-token","annotations":{"team":"coco"}}`, func(c *ClientV2) (any, error) {
			return c.CreateDynamicSecret(dynamicSafeName, DynamicSecretCreate{Name: "dyn2", Issuer: "test-issuer-aws", TTL: 900, Method: "federation-token", Annotations: map[string]string{"team": "coco"}})
		}, assertDynamicSecret},
		{"ListManagedSafeSecrets", http.StatusOK, managedListJSON, http.MethodGet, "/safes/managed/test_safe/secrets", "filter=aws+key&limit=10&offset=5", "", func(c *ClientV2) (any, error) {
			return c.ListManagedSecrets(managedSafeName, listParams)
		}, func(t *testing.T, got any) {
			list, ok := got.(*ManagedSecretList)
			require.True(t, ok, "got %T", got)
			assert.Equal(t, 1, list.Count)
			require.Len(t, list.Secrets, 1)
			secret := list.Secrets[0]
			assert.Equal(t, "aws-secret-access-key", secret.Name)
			assert.NotNil(t, secret.Annotations)
			assert.Empty(t, secret.Annotations)
			assert.Equal(t, "text/plain", secret.MimeType)
			assert.Equal(t, 3, secret.Version)
			assert.Equal(t, "2026-10-02T13:50:10.348+00:00", secret.CreatedAt)
			assert.Equal(t, "2026-10-02T13:50:10.348+00:00", secret.LastUpdated)
			assert.Nil(t, secret.Replicated)
			assert.Equal(t, &SafeDetails{Type: "managed", Name: "test_safe", Replicated: false}, secret.Safe)
		}},
		{"ListDynamicSafeSecrets", http.StatusOK, dynamicListJSON, http.MethodGet, "/safes/dynamic/test_dynamic_safe/secrets", "filter=aws+key&limit=10&offset=5", "", func(c *ClientV2) (any, error) {
			return c.ListDynamicSecrets(dynamicSafeName, listParams)
		}, func(t *testing.T, got any) {
			list, ok := got.(*DynamicSecretList)
			require.True(t, ok, "got %T", got)
			assert.Equal(t, 1, list.Count)
			require.Len(t, list.Secrets, 1)
			secret := list.Secrets[0]
			assert.Equal(t, "dyn2", secret.Name)
			assert.NotNil(t, secret.Annotations)
			assert.Empty(t, secret.Annotations)
			assert.Equal(t, wantDynamicParams, secret.DynamicParams)
			assert.Equal(t, "2026-10-05T09:31:43.849+00:00", secret.CreatedAt)
			assert.Nil(t, secret.Replicated)
			assert.Equal(t, &SafeDetails{Type: "dynamic", Name: "test_dynamic_safe", Replicated: false}, secret.Safe)
		}},
		{"GetManagedSafeSecretMetadata", http.StatusOK, managedSecretJSON, http.MethodGet, "/safes/managed/test_safe/secrets/aws-secret-access-key", "", "", func(c *ClientV2) (any, error) {
			return c.GetManagedSecretMetadata(managedSafeName, "aws-secret-access-key")
		}, assertManagedSecret},
		{"GetDynamicSafeSecretMetadata", http.StatusOK, dynamicSecretJSON, http.MethodGet, "/safes/dynamic/test_dynamic_safe/secrets/dyn2", "", "", func(c *ClientV2) (any, error) {
			return c.GetDynamicSecretMetadata(dynamicSafeName, "dyn2")
		}, assertDynamicSecret},
		{"PatchManagedSafeSecret", http.StatusOK, managedSecretJSON, http.MethodPatch, "/safes/managed/test_safe/secrets/aws-secret-access-key", "", `{"value":"n3w","annotations":{"team":"coco"}}`, func(c *ClientV2) (any, error) {
			return c.PatchManagedSecret(managedSafeName, "aws-secret-access-key", ManagedSecretUpdate{Value: "n3w", Annotations: map[string]string{"team": "coco"}})
		}, assertManagedSecret},
		{"PatchDynamicSafeSecret", http.StatusOK, dynamicSecretJSON, http.MethodPatch, "/safes/dynamic/test_dynamic_safe/secrets/dyn2", "", `{"ttl":1800}`, func(c *ClientV2) (any, error) {
			return c.PatchDynamicSecret(dynamicSafeName, "dyn2", DynamicSecretUpdate{TTL: 1800})
		}, assertDynamicSecret},
		{"ReplaceManagedSafeSecret", http.StatusOK, managedSecretJSON, http.MethodPut, "/safes/managed/test_safe/secrets/aws-secret-access-key", "", `{"mime_type":"text/plain"}`, func(c *ClientV2) (any, error) {
			return c.ReplaceManagedSecret(managedSafeName, "aws-secret-access-key", ManagedSecretUpdate{MimeType: "text/plain"})
		}, assertManagedSecret},
		{"ReplaceDynamicSafeSecret", http.StatusOK, dynamicSecretJSON, http.MethodPut, "/safes/dynamic/test_dynamic_safe/secrets/dyn2", "", `{"issuer":"test-issuer-aws","ttl":900,"method":"federation-token","method_params":{"region":"us-east-1"}}`, func(c *ClientV2) (any, error) {
			return c.ReplaceDynamicSecret(dynamicSafeName, "dyn2", DynamicSecretUpdate{Issuer: "test-issuer-aws", TTL: 900, Method: "federation-token", MethodParams: map[string]any{"region": "us-east-1"}})
		}, assertDynamicSecret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, captured := newSafeSecretMockServer(t, tc.status, "application/json", []byte(tc.respBody))

			got, err := tc.call(c)
			require.NoError(t, err)

			assert.Equal(t, 1, captured.calls)
			assert.Equal(t, tc.wantMethod, captured.method)
			assert.Equal(t, tc.wantPath, captured.path)
			assert.Equal(t, tc.wantQuery, captured.rawQuery)
			assert.Equal(t, v2APIHeaderBeta, captured.accept)
			if tc.wantBody == "" {
				assert.Empty(t, captured.body)
			} else {
				assert.JSONEq(t, tc.wantBody, captured.body)
			}
			tc.check(t, got)
		})
	}
}

func TestSafeSecretValue_ReturnsRawBytes(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        []byte
		version     int
		wantQuery   string
	}{
		{"binary, version 2", "application/octet-stream", []byte{0x00, 0xff, 0xfe, 'a', '\n'}, 2, "version=2"},
		{"binary, latest", "application/octet-stream", []byte{0x00, 0xff, 0xfe, 'a', '\n'}, 0, ""},
		{"text, version 2", "text/plain", []byte("s3cr3t value\n"), 2, "version=2"},
		{"text, latest", "text/plain", []byte("s3cr3t value\n"), 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, captured := newSafeSecretMockServer(t, http.StatusOK, tc.contentType, tc.body)

			value, err := c.GetManagedSecretValue("test_safe", "aws-secret-access-key", tc.version)
			require.NoError(t, err)
			require.NotNil(t, value)
			assert.Equal(t, tc.body, value.Value)
			assert.Equal(t, tc.contentType, value.MimeType)

			assert.Equal(t, http.MethodGet, captured.method)
			assert.Equal(t, "/safes/managed/test_safe/secrets/aws-secret-access-key/value", captured.path)
			assert.Equal(t, tc.wantQuery, captured.rawQuery)
			assert.Equal(t, v2APIHeaderBeta, captured.accept)
		})
	}
}

func TestSafeSecretSetValue_SendsRawBytes(t *testing.T) {
	respBody := `{"name":"aws-secret-access-key","annotations":{"team":"coco"},"mime_type":"application/octet-stream","created_at":"2026-10-02T13:50:10.348+00:00","version":4,"last_updated":"2026-10-07T12:00:00.000+00:00","replicated":false,"safe":{"type":"managed","name":"test_safe","replicated":false}}`
	cases := []struct {
		name     string
		value    []byte
		mimeType string
	}{
		{"binary", []byte{0x20, 0x20, 0x61, 0xFF, 0xFE, 0x80, 0xC3, 0x62, 0xE2, 0x82, 0x63, 0xC0, 0xAF, 0xED, 0xA0, 0x80, 0xF4, 0x90, 0x80, 0x80, 0x64, 0x20, 0x20, 0x0A}, "application/octet-stream"},
		{"text", []byte("  s3cr3t value\n"), "text/plain; charset=utf-8"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, captured := newSafeSecretMockServer(t, http.StatusOK, "application/json", []byte(respBody))

			secret, err := c.SetManagedSecretValue("test_safe", "aws-secret-access-key", tc.value, tc.mimeType)
			require.NoError(t, err)
			require.NotNil(t, secret)
			assert.Equal(t, "aws-secret-access-key", secret.Name)
			assert.Equal(t, map[string]string{"team": "coco"}, secret.Annotations)
			assert.Equal(t, "application/octet-stream", secret.MimeType)
			assert.Equal(t, "2026-10-02T13:50:10.348+00:00", secret.CreatedAt)
			assert.Equal(t, 4, secret.Version)
			assert.Equal(t, "2026-10-07T12:00:00.000+00:00", secret.LastUpdated)
			require.NotNil(t, secret.Replicated)
			assert.False(t, *secret.Replicated)
			assert.Equal(t, &SafeDetails{Type: "managed", Name: "test_safe", Replicated: false}, secret.Safe)

			assert.Equal(t, 1, captured.calls)
			assert.Equal(t, http.MethodPut, captured.method)
			assert.Equal(t, "/safes/managed/test_safe/secrets/aws-secret-access-key/value", captured.path)
			assert.Empty(t, captured.rawQuery)
			assert.Equal(t, v2APIHeaderBeta, captured.accept)
			assert.Equal(t, tc.mimeType, captured.contentType)
			assert.Equal(t, tc.value, []byte(captured.body))
		})
	}
}

func TestSafeSecretDynamicValue_Decodes(t *testing.T) {
	body := `{"id":"dyn-value-1","ttl":900,"data":{"access_key_id":"AKIAEXAMPLE","secret_access_key":"wJalrXUtnFEMI","nested":{"region":"us-east-1","expires_in":900}}}`
	c, captured := newSafeSecretMockServer(t, http.StatusOK, "application/json", []byte(body))

	value, err := c.GetDynamicSecretValue("test_dynamic_safe", "dyn2")
	require.NoError(t, err)
	require.NotNil(t, value)
	assert.Equal(t, "dyn-value-1", value.Id)
	assert.Equal(t, 900, value.TTL)
	assert.Equal(t, map[string]any{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "wJalrXUtnFEMI", "nested": map[string]any{"region": "us-east-1", "expires_in": float64(900)}}, value.Data)

	assert.Equal(t, http.MethodGet, captured.method)
	assert.Equal(t, "/safes/dynamic/test_dynamic_safe/secrets/dyn2/value", captured.path)
	assert.Empty(t, captured.rawQuery)
	assert.Equal(t, v2APIHeaderBeta, captured.accept)
}

func TestSafeSecretDelete_NoContent(t *testing.T) {
	c, captured := newSafeSecretMockServer(t, http.StatusNoContent, "", nil)

	err := c.DeleteSecret("managed", "test_safe", "aws-secret-access-key")
	require.NoError(t, err)

	assert.Equal(t, 1, captured.calls)
	assert.Equal(t, http.MethodDelete, captured.method)
	assert.Equal(t, "/safes/managed/test_safe/secrets/aws-secret-access-key", captured.path)
	assert.Empty(t, captured.rawQuery)
	assert.Equal(t, v2APIHeaderBeta, captured.accept)
	assert.Empty(t, captured.body)
}

func TestSafeSecretWrappers_ErrorResponses(t *testing.T) {
	statuses := []struct {
		status  int
		code    string
		message string
	}{
		{http.StatusNotFound, "not_found", "Secret not found"},
		{http.StatusConflict, "conflict", "Secret already exists"},
		{http.StatusUnprocessableEntity, "unprocessable_entity", "Invalid secret parameters"},
	}

	for _, st := range statuses {
		body := []byte(`{"error":{"code":"` + st.code + `","message":"` + st.message + `"}}`)
		for i, w := range safeSecretWrappers(nil) {
			t.Run(http.StatusText(st.status)+"/"+w.name, func(t *testing.T) {
				c, captured := newSafeSecretMockServer(t, st.status, "application/json", body)

				got, err := safeSecretWrappers(c)[i].call(testSafeName)
				require.Error(t, err)
				assert.Nil(t, got)
				assert.Equal(t, 1, captured.calls)

				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr), "error %T: %v", err, err)
				assert.Equal(t, st.status, cerr.Code)
				require.NotNil(t, cerr.Details)
				assert.Equal(t, st.code, cerr.Details.Code)
				assert.Equal(t, st.message, cerr.Details.Message)
				assert.Contains(t, err.Error(), st.message)
			})
		}
	}
}

func TestSafeSecretWrappers_InvalidResponseBody(t *testing.T) {
	for i, w := range safeSecretWrappers(nil) {
		if !w.typed {
			continue
		}
		t.Run(w.name, func(t *testing.T) {
			c, captured := newSafeSecretMockServer(t, http.StatusOK, "application/json", []byte(`not json`))

			got, err := safeSecretWrappers(c)[i].call(testSafeName)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Equal(t, 1, captured.calls)
		})
	}
}

func TestSafeSecretWrappers_PropagateRequestBuildErrors(t *testing.T) {
	client := newAuthenticatedMockServer(t, EnvironmentSaaS, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for an invalid request: %s %s", r.Method, r.URL.Path)
	})

	wrappers := safeSecretWrappers(client.V2())
	require.Len(t, wrappers, 14)
	for _, w := range wrappers {
		t.Run(w.name, func(t *testing.T) {
			got, err := w.call("")
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), "Must specify a Safe name")
		})
	}
}

func TestSafeSecretWrappers_RejectNonSaaS(t *testing.T) {
	client := newAuthenticatedMockServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/safes/") {
			t.Errorf("non-SaaS request should not reach the safes route: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	})

	for _, w := range safeSecretWrappers(client.V2()) {
		t.Run(w.name, func(t *testing.T) {
			got, err := w.call(testSafeName)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), "Safes API is not supported in Idira Secrets Manager/Conjur OSS")
		})
	}
}
