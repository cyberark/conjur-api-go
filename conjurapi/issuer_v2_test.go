package conjurapi

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "testIssuer"

func TestClientV2_CertificateIssueRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	issuerName := testIssuer

	issue := Issue{}
	issue.Subject = IssuerSubject{}

	_, err = client.V2().CertificateIssueRequest(issuerName, issue)

	assert.Contains(t, err.Error(), "Subject attribute CommonName")

	issue.Subject = IssuerSubject{CommonName: "CommonName"}

	request, err := client.V2().CertificateIssueRequest(issuerName, issue)
	require.NoError(t, err)

	assert.Equal(t, request.Header.Get(v2APIOutgoingHeaderID), v2APIHeaderBeta)
	assert.Equal(t, "application/json", request.Header.Get("Content-Type"))

	request, err = client.V2().CertificateIssueRequest(issuerName, issue)
	require.NoError(t, err)

	reqURL := "localhost/issuers/" + issuerName + "/issue"
	assert.Equal(t, request.URL.Path, reqURL)

	assert.Equal(t, request.Method, http.MethodPost)
}

func TestClientV2_CertificateSignRequest(t *testing.T) {
	config := GetConfigForTest("localhost")
	client, err := NewClientFromJwt(config)
	issuerName := testIssuer

	sign := Sign{}

	_, err = client.V2().CertificateSignRequest(issuerName, sign)
	assert.Contains(t, err.Error(), "Sign attribute csr")

	sign.Csr = "csr"

	request, err := client.V2().CertificateSignRequest(issuerName, sign)
	require.NoError(t, err)

	assert.Equal(t, request.Header.Get(v2APIOutgoingHeaderID), v2APIHeaderBeta)
	assert.Equal(t, "application/json", request.Header.Get("Content-Type"))

	request, err = client.V2().CertificateSignRequest(issuerName, sign)
	require.NoError(t, err)

	reqURL := "localhost/issuers/" + issuerName + "/sign"
	assert.Equal(t, request.URL.Path, reqURL)

	assert.Equal(t, request.Method, http.MethodPost)
}

func TestClient_CreateIssuerV2Issue(t *testing.T) {
	if strings.ToLower(os.Getenv("ENV_VENIFY_CONF_SET")) != "true" {
		t.Skip("Skipping Certificate Issue test")
	}
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	testCases := []struct {
		name              string
		id                string
		issuerType        string
		maxTTL            int
		data              map[string]interface{}
		assertIssuer      func(*testing.T, Issuer)
		expectError       string
		issue             Issue
		subjectCommonName string
	}{
		{
			name:       "Issue cert",
			id:         "test-issuer-2",
			issuerType: "aws",
			maxTTL:     900,
			data: map[string]interface{}{
				"access_key_id":     TestAccessKeyID,
				"secret_access_key": TestSecretAccessKey,
			},
			issue:             Issue{},
			subjectCommonName: "name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := Issuer{
				ID:     tc.id,
				Type:   tc.issuerType,
				MaxTTL: tc.maxTTL,
				Data:   tc.data,
			}

			createdIssuer, err := conjur.CreateIssuer(issuer)
			assert.NoError(t, err)

			assert.Equal(t, "test-issuer-2", createdIssuer.ID)
			assert.Equal(t, "aws", createdIssuer.Type)
			assert.Equal(t, 900, createdIssuer.MaxTTL)
			assert.Equal(t, TestAccessKeyID, createdIssuer.Data["access_key_id"])
			// Expect masked response for the access key
			assert.Equal(t, "*****", createdIssuer.Data["secret_access_key"])
			assert.NotEmpty(t, createdIssuer.CreatedAt)
			assert.NotEmpty(t, createdIssuer.ModifiedAt)

			if tc.subjectCommonName != "" {
				tc.issue.Subject.CommonName = tc.subjectCommonName
			}
			locIssue, err := conjur.V2().CertificateIssue(createdIssuer.ID, tc.issue)
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {

				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, locIssue)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}

			// Clean up the Issuer, if it was created
			err = conjur.DeleteIssuer(tc.id, false)
			assert.NoError(t, err)
		})
	}
}

func TestClient_CreateIssuerV2Sign(t *testing.T) {
	if strings.ToLower(os.Getenv("ENV_VENIFY_CONF_SET")) != "true" {
		t.Skip("Skipping Create Issuer Sign test")
	}
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()

	testCases := []struct {
		name         string
		id           string
		issuerType   string
		maxTTL       int
		data         map[string]interface{}
		assertIssuer func(*testing.T, Issuer)
		expectError  string
		sign         Sign
	}{
		{
			name:       "Sign certificate",
			id:         "test-issuer-3",
			issuerType: "aws",
			maxTTL:     900,
			data: map[string]interface{}{
				"access_key_id":     TestAccessKeyID,
				"secret_access_key": TestSecretAccessKey,
			},
			sign: Sign{Csr: "-----BEGIN CERTIFICATE REQUEST-----123-----END CERTIFICATE REQUEST-----"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := Issuer{
				ID:     tc.id,
				Type:   tc.issuerType,
				MaxTTL: tc.maxTTL,
				Data:   tc.data,
			}

			createdIssuer, err := conjur.CreateIssuer(issuer)
			assert.NoError(t, err)

			assert.Equal(t, "test-issuer-3", createdIssuer.ID)
			assert.Equal(t, "aws", createdIssuer.Type)
			assert.Equal(t, 900, createdIssuer.MaxTTL)
			assert.Equal(t, TestAccessKeyID, createdIssuer.Data["access_key_id"])
			// Expect masked response for the access key
			assert.Equal(t, "*****", createdIssuer.Data["secret_access_key"])
			assert.NotEmpty(t, createdIssuer.CreatedAt)
			assert.NotEmpty(t, createdIssuer.ModifiedAt)

			locIssue, err := conjur.V2().CertificateSign(createdIssuer.ID, tc.sign)
			if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {

				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
				} else {
					require.NoError(t, err)
					assert.NotNil(t, locIssue)
				}
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "is not supported in Conjur Enterprise/OSS")
				return
			}

			// Clean up the Issuer, if it was created
			err = conjur.DeleteIssuer(tc.id, false)
			assert.NoError(t, err)
		})
	}
}
