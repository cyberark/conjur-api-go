package conjurapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// safeSecretTestSuffix makes names unique per run, since a tenant may be reused between local runs and issuer IDs are unique across the whole tenant.
func safeSecretTestSuffix() string {
	return testGeneratedSecret()[:8]
}

// newSafeSecretTestClient gates the test on safe secrets support and returns a client with the policy reset.
func newSafeSecretTestClient(t *testing.T) (TestUtils, *ClientV2) {
	t.Helper()

	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	SkipIfUnsupported(t, utils.Client(), contract.CapabilitySafesV2)

	_, err = utils.Setup("#")
	require.NoError(t, err)

	return utils, utils.Client().V2()
}

// createSafeSecretTestSafe creates a safe and registers its deletion. Cleanups registered after this run first, so secrets registered later are deleted before the safe.
func createSafeSecretTestSafe(t *testing.T, conjur *ClientV2, safeType, safeName string) {
	t.Helper()

	_, err := conjur.CreateSafe(Safe{Type: safeType, Name: safeName})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conjur.DeleteSafe(safeType, safeName); err != nil {
			t.Logf("failed to clean up safe %s/%s: %s", safeType, safeName, err)
		}
	})
}

// cleanupSafeSecret registers a best-effort deletion of a secret, for when the test stops before deleting it.
func cleanupSafeSecret(t *testing.T, conjur *ClientV2, safeType, safeName, secretName string) {
	t.Helper()

	t.Cleanup(func() {
		_ = conjur.DeleteSecret(safeType, safeName, secretName)
	})
}

func requireConjurErrorCode(t *testing.T, err error, code int) {
	t.Helper()

	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	require.Equal(t, code, conjurErr.Code)
}

// safeSecretStepper returns a function that runs ordered subtests of t, stopping t at the first failing one.
func safeSecretStepper(t *testing.T) func(name string, f func(t *testing.T)) {
	return func(name string, f func(t *testing.T)) {
		if !t.Run(name, f) {
			t.FailNow()
		}
	}
}

func TestClientV2_ManagedSafeSecretLifecycle(t *testing.T) {
	_, conjur := newSafeSecretTestClient(t)

	suffix := safeSecretTestSuffix()
	safeName := "api_go_managed_safe_" + suffix
	secretName := "api-go-secret-" + suffix
	secondSecretName := secretName + "-2"
	createSafeSecretTestSafe(t, conjur, "managed", safeName)
	cleanupSafeSecret(t, conjur, "managed", safeName, secretName)

	const versionBugMsg = "the version must increment whenever the value is set; if it doesn't, this is a server bug to report to the Conjur Cloud team"
	const textMime = "text/plain"
	binaryValue := []byte{0x20, 0x20, 0x61, 0xFF, 0xFE, 0x80, 0xC3, 0x62, 0xE2, 0x82, 0x63, 0xC0, 0xAF, 0xED, 0xA0, 0x80, 0xF4, 0x90, 0x80, 0x80, 0x64, 0x20, 0x20, 0x0A}
	textValue := []byte("  text value with whitespace \t\n")

	step := safeSecretStepper(t)

	step("create", func(t *testing.T) {
		created, err := conjur.CreateManagedSecret(safeName, ManagedSecretCreate{
			Name: secretName, Value: "value-v1", MimeType: textMime, Annotations: map[string]string{"team": "coco"},
		})
		require.NoError(t, err)
		assert.Equal(t, secretName, created.Name)
		assert.Equal(t, 1, created.Version)
		assert.Equal(t, textMime, created.MimeType)
		assert.Equal(t, map[string]string{"team": "coco"}, created.Annotations)
	})

	step("duplicate create returns 409", func(t *testing.T) {
		_, err := conjur.CreateManagedSecret(safeName, ManagedSecretCreate{Name: secretName, Value: "duplicate"})
		requireConjurErrorCode(t, err, http.StatusConflict)
	})

	step("get metadata", func(t *testing.T) {
		secret, err := conjur.GetManagedSecretMetadata(safeName, secretName)
		require.NoError(t, err)
		assert.Equal(t, secretName, secret.Name)
		assert.Equal(t, 1, secret.Version)
		assert.Equal(t, textMime, secret.MimeType)
		assert.Equal(t, map[string]string{"team": "coco"}, secret.Annotations)
	})

	step("get latest value", func(t *testing.T) {
		value, err := conjur.GetManagedSecretValue(safeName, secretName, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte("value-v1"), value.Value)
		assert.Equal(t, textMime, value.MimeType)
	})

	step("patch value and annotation", func(t *testing.T) {
		patched, err := conjur.PatchManagedSecret(safeName, secretName, ManagedSecretUpdate{Value: "value-v2", Annotations: map[string]string{"env": "test"}})
		require.NoError(t, err)
		require.Equal(t, 2, patched.Version, versionBugMsg)
		assert.Equal(t, map[string]string{"team": "coco", "env": "test"}, patched.Annotations)
		assert.Equal(t, textMime, patched.MimeType)
	})

	step("annotation-only patch keeps the version", func(t *testing.T) {
		patched, err := conjur.PatchManagedSecret(safeName, secretName, ManagedSecretUpdate{Annotations: map[string]string{"owner": "api-go"}})
		require.NoError(t, err)
		require.Equal(t, 2, patched.Version)
		assert.Equal(t, map[string]string{"team": "coco", "env": "test", "owner": "api-go"}, patched.Annotations)
		assert.Equal(t, textMime, patched.MimeType)
	})

	step("set binary value", func(t *testing.T) {
		secret, err := conjur.SetManagedSecretValue(safeName, secretName, binaryValue, "application/octet-stream")
		require.NoError(t, err)
		require.Equal(t, 3, secret.Version, versionBugMsg)
		assert.Equal(t, "application/octet-stream", secret.MimeType)

		value, err := conjur.GetManagedSecretValue(safeName, secretName, 0)
		require.NoError(t, err)
		assert.Equal(t, binaryValue, value.Value)
		assert.Equal(t, "application/octet-stream", value.MimeType)
	})

	step("set text value preserves whitespace", func(t *testing.T) {
		secret, err := conjur.SetManagedSecretValue(safeName, secretName, textValue, textMime)
		require.NoError(t, err)
		require.Equal(t, 4, secret.Version, versionBugMsg)
		assert.Equal(t, textMime, secret.MimeType)

		value, err := conjur.GetManagedSecretValue(safeName, secretName, 0)
		require.NoError(t, err)
		assert.Equal(t, textValue, value.Value)
		assert.Equal(t, textMime, value.MimeType)
	})

	step("value-only patch keeps the mime type", func(t *testing.T) {
		patched, err := conjur.PatchManagedSecret(safeName, secretName, ManagedSecretUpdate{Value: "value-v5"})
		require.NoError(t, err)
		require.Equal(t, 5, patched.Version, versionBugMsg)
		assert.Equal(t, textMime, patched.MimeType)
	})

	step("get value by version", func(t *testing.T) {
		for version, expected := range map[int][]byte{1: []byte("value-v1"), 3: binaryValue, 5: []byte("value-v5")} {
			value, err := conjur.GetManagedSecretValue(safeName, secretName, version)
			require.NoError(t, err, "version %d", version)
			assert.Equal(t, expected, value.Value, "version %d", version)
		}
	})

	step("replace without value", func(t *testing.T) {
		replaced, err := conjur.ReplaceManagedSecret(safeName, secretName, ManagedSecretUpdate{Annotations: map[string]string{"replaced": "yes"}})
		require.NoError(t, err)
		require.Equal(t, 5, replaced.Version)
		assert.Equal(t, map[string]string{"replaced": "yes"}, replaced.Annotations)
		assert.Equal(t, "", replaced.MimeType)

		value, err := conjur.GetManagedSecretValue(safeName, secretName, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte("value-v5"), value.Value)
	})

	step("replace with value", func(t *testing.T) {
		replaced, err := conjur.ReplaceManagedSecret(safeName, secretName, ManagedSecretUpdate{Value: `{"key":"value-v6"}`, MimeType: "application/json"})
		require.NoError(t, err)
		require.Equal(t, 6, replaced.Version, versionBugMsg)
		assert.Equal(t, "application/json", replaced.MimeType)
		assert.Empty(t, replaced.Annotations)

		value, err := conjur.GetManagedSecretValue(safeName, secretName, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte(`{"key":"value-v6"}`), value.Value)
		assert.Equal(t, "application/json", value.MimeType)
	})

	cleanupSafeSecret(t, conjur, "managed", safeName, secondSecretName)
	step("list", func(t *testing.T) {
		_, err := conjur.CreateManagedSecret(safeName, ManagedSecretCreate{Name: secondSecretName, Value: "second-value"})
		require.NoError(t, err)

		filter := "name contains " + suffix
		list, err := conjur.ListManagedSecrets(safeName, ListSafeSecretParams{Filter: filter})
		require.NoError(t, err)
		var names []string
		for _, secret := range list.Secrets {
			names = append(names, secret.Name)
		}
		assert.Contains(t, names, secretName)
		assert.Contains(t, names, secondSecretName)

		first, err := conjur.ListManagedSecrets(safeName, ListSafeSecretParams{Limit: 1, Offset: 0, Filter: filter})
		require.NoError(t, err)
		require.Len(t, first.Secrets, 1)
		second, err := conjur.ListManagedSecrets(safeName, ListSafeSecretParams{Limit: 1, Offset: 1, Filter: filter})
		require.NoError(t, err)
		require.Len(t, second.Secrets, 1)
		assert.NotEqual(t, first.Secrets[0].Name, second.Secrets[0].Name)
	})

	step("delete", func(t *testing.T) {
		require.NoError(t, conjur.DeleteSecret("managed", safeName, secretName))

		_, err := conjur.GetManagedSecretMetadata(safeName, secretName)
		requireConjurErrorCode(t, err, http.StatusNotFound)

		err = conjur.DeleteSecret("managed", safeName, secretName)
		requireConjurErrorCode(t, err, http.StatusNotFound)
	})
}

func TestClientV2_DynamicSafeSecretLifecycle(t *testing.T) {
	utils, conjur := newSafeSecretTestClient(t)

	suffix := safeSecretTestSuffix()
	issuerID := "api-go-safe-secret-issuer-" + suffix
	safeName := "api_go_dynamic_safe_" + suffix
	federationTokenSecretName := "api-go-dynamic-secret-" + suffix
	assumeRoleSecretName := "api-go-assume-role-secret-" + suffix
	const region = "us-east-1"
	const roleARN = "arn:aws:iam::123456789012:role/test-role"
	const inlinePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	setupIssuerAWSCredentials(t, utils, utils.Client())
	_, err := utils.Client().CreateIssuer(newTestAWSIssuer(issuerID, 1200))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := utils.Client().DeleteIssuer(issuerID, false); err != nil {
			t.Logf("failed to clean up issuer %s: %s", issuerID, err)
		}
	})

	createSafeSecretTestSafe(t, conjur, "dynamic", safeName)
	cleanupSafeSecret(t, conjur, "dynamic", safeName, federationTokenSecretName)
	cleanupSafeSecret(t, conjur, "dynamic", safeName, assumeRoleSecretName)

	step := safeSecretStepper(t)

	step("create federation-token secret", func(t *testing.T) {
		created, err := conjur.CreateDynamicSecret(safeName, DynamicSecretCreate{
			Name: federationTokenSecretName, Issuer: issuerID, TTL: 1200, Method: "federation-token",
			MethodParams: map[string]any{"region": region}, Annotations: map[string]string{"team": "coco"},
		})
		require.NoError(t, err)
		assert.Equal(t, federationTokenSecretName, created.Name)
		assert.Equal(t, map[string]string{"team": "coco"}, created.Annotations)
		assert.Equal(t, issuerID, created.DynamicParams.Issuer)
		assert.Equal(t, "aws", created.DynamicParams.IssuerType)
		assert.Equal(t, "federation-token", created.DynamicParams.Method)
		assert.Equal(t, new(1200), created.DynamicParams.TTL)
		assert.Equal(t, map[string]any{"region": region}, created.DynamicParams.MethodParams)
	})

	step("duplicate create returns 409", func(t *testing.T) {
		_, err := conjur.CreateDynamicSecret(safeName, DynamicSecretCreate{
			Name: federationTokenSecretName, Issuer: issuerID, TTL: 1200, Method: "federation-token", MethodParams: map[string]any{"region": region},
		})
		requireConjurErrorCode(t, err, http.StatusConflict)
	})

	step("get metadata", func(t *testing.T) {
		secret, err := conjur.GetDynamicSecretMetadata(safeName, federationTokenSecretName)
		require.NoError(t, err)
		assert.Equal(t, federationTokenSecretName, secret.Name)
		assert.Equal(t, map[string]string{"team": "coco"}, secret.Annotations)
		assert.Equal(t, issuerID, secret.DynamicParams.Issuer)
		assert.Equal(t, "aws", secret.DynamicParams.IssuerType)
		assert.Equal(t, "federation-token", secret.DynamicParams.Method)
		assert.Equal(t, new(1200), secret.DynamicParams.TTL)
		assert.Equal(t, map[string]any{"region": region}, secret.DynamicParams.MethodParams)
		assert.NotEmpty(t, secret.CreatedAt)
	})

	step("list with filter", func(t *testing.T) {
		list, err := conjur.ListDynamicSecrets(safeName, ListSafeSecretParams{Filter: "name contains " + suffix})
		require.NoError(t, err)
		var names []string
		for _, secret := range list.Secrets {
			names = append(names, secret.Name)
		}
		assert.Contains(t, names, federationTokenSecretName)
	})

	step("patch annotations and ttl", func(t *testing.T) {
		patched, err := conjur.PatchDynamicSecret(safeName, federationTokenSecretName, DynamicSecretUpdate{TTL: 1000, Annotations: map[string]string{"owner": "api-go"}})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"team": "coco", "owner": "api-go"}, patched.Annotations)
		assert.Equal(t, new(1000), patched.DynamicParams.TTL)
		assert.Equal(t, issuerID, patched.DynamicParams.Issuer)
		assert.Equal(t, "federation-token", patched.DynamicParams.Method)
	})

	step("replace without ttl clears it", func(t *testing.T) {
		replaced, err := conjur.ReplaceDynamicSecret(safeName, federationTokenSecretName, DynamicSecretUpdate{
			Issuer: issuerID, Method: "federation-token", Annotations: map[string]string{"stage": "replaced"},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"stage": "replaced"}, replaced.Annotations)
		assert.Nil(t, replaced.DynamicParams.TTL)
		assert.Equal(t, issuerID, replaced.DynamicParams.Issuer)
		assert.Equal(t, "federation-token", replaced.DynamicParams.Method)
		assert.Equal(t, map[string]any{}, replaced.DynamicParams.MethodParams)
	})

	step("delete", func(t *testing.T) {
		require.NoError(t, conjur.DeleteSecret("dynamic", safeName, federationTokenSecretName))

		_, err := conjur.GetDynamicSecretMetadata(safeName, federationTokenSecretName)
		requireConjurErrorCode(t, err, http.StatusNotFound)
	})

	step("assume-role", func(t *testing.T) {
		created, err := conjur.CreateDynamicSecret(safeName, DynamicSecretCreate{
			Name: assumeRoleSecretName, Issuer: issuerID, Method: "assume-role", MethodParams: map[string]any{"role_arn": roleARN, "region": region, "inline_policy": inlinePolicy},
		})
		require.NoError(t, err)
		assert.Equal(t, "assume-role", created.DynamicParams.Method)
		methodParams := created.DynamicParams.MethodParams
		assert.Equal(t, roleARN, methodParams["role_arn"])
		assert.Equal(t, region, methodParams["region"])
		policy, ok := methodParams["inline_policy"].(string)
		require.True(t, ok, "inline_policy should be a string, got %#v", methodParams["inline_policy"])
		assert.JSONEq(t, inlinePolicy, policy)

		patched, err := conjur.PatchDynamicSecret(safeName, assumeRoleSecretName, DynamicSecretUpdate{Method: "federation-token"})
		require.NoError(t, err)
		assert.Equal(t, "federation-token", patched.DynamicParams.Method)
		assert.NotContains(t, patched.DynamicParams.MethodParams, "role_arn")

		require.NoError(t, conjur.DeleteSecret("dynamic", safeName, assumeRoleSecretName))
	})
}
