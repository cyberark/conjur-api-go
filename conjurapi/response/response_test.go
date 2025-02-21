package response

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactHeaders(t *testing.T) {
	t.Run("Test redacts headers", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"Bearer super_secret_access_token"},
			"Content-Type":  []string{"application/json"},
		}

		newHeaders := redactHeaders(headers)
		assert.Equal(t, "[REDACTED]", newHeaders.Get("Authorization"))
		assert.Equal(t, "application/json", newHeaders.Get("Content-Type"))

		// Ensure the original headers are not modified
		assert.Equal(t, "Bearer super_secret_access_token", headers.Get("Authorization"))
	})
}

func TestLogResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response *http.Response
		assert   func(*testing.T, *bytes.Buffer)
	}{
		{
			name: "Test redacts Authorization header on successful response",
			response: &http.Response{
				StatusCode: 200,
				Request:    goodRequest(),
			},
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				assert.Contains(t, logOutput.String(), "200 GET https://example.com map[Authorization:")
				assert.Contains(t, logOutput.String(), "Content-Type:[application/json]]")
				// Make sure the authorization header is redacted
				assert.NotContains(t, logOutput.String(), "super_secret_access_token")
			},
		},
		{
			name: "Test redacts Authorization header on failed response",
			response: &http.Response{
				StatusCode: 401,
				Request: &http.Request{
					Method: "POST",
					URL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
					},
					Header: http.Header{
						"Authorization": []string{"Bearer super_secret_access_token"},
					},
				},
			},
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				assert.Contains(t, logOutput.String(), "401 POST https://example.com map[Authorization:")
				// Make sure the authorization header is redacted
				assert.NotContains(t, logOutput.String(), "super_secret_access_token")
			},
		},
		{
			name: "Test redacts multiple Authorization headers",
			response: &http.Response{
				StatusCode: 200,
				Request: &http.Request{
					Method: "GET",
					URL: &url.URL{
						Scheme: "https",
						Host:   "example.com",
					},
					Header: http.Header{
						"Authorization": []string{"Bearer super_secret_access_token", "Bearer another_secret_token"},
					},
				},
			},
			assert: func(t *testing.T, logOutput *bytes.Buffer) {
				assert.Contains(t, logOutput.String(), "200 GET https://example.com map[Authorization:")
				// Make sure the authorization headers are redacted
				assert.NotContains(t, logOutput.String(), "super_secret_access_token")
				assert.NotContains(t, logOutput.String(), "another_secret_token")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Intercept the log output
			var logOutput bytes.Buffer
			logging.ApiLog.SetOutput(&logOutput)
			// Set the log level to debug to capture all logs
			logging.ApiLog.SetLevel(logrus.DebugLevel)

			logResponse(tc.response)

			tc.assert(t, &logOutput)

			// Reset the log output
			t.Cleanup(func() {
				logging.ApiLog.SetOutput(os.Stdout)
				logging.ApiLog.SetLevel(logrus.InfoLevel)
			})
		})
	}
}

func TestDataResponse(t *testing.T) {
	testCases := []struct {
		name          string
		response      *http.Response
		expectedBody  []byte
		expectedError string
	}{
		{
			name:          "Test successful response",
			response:      goodResponse(),
			expectedBody:  []byte("response body"),
			expectedError: "",
		},
		{
			name:          "Test failed response",
			response:      badResponse(),
			expectedBody:  nil,
			expectedError: "error message",
		},
		{
			name: "Error reading response body",
			response: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(errorReader{}),
				Request:    goodRequest(),
			},
			expectedBody:  nil,
			expectedError: "test read error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := DataResponse(tc.response)

			assert.Equal(t, tc.expectedBody, body)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecretDataResponse(t *testing.T) {
	testCases := []struct {
		name          string
		response      *http.Response
		expectedBody  []byte
		expectedError string
	}{
		{
			name:          "Test successful response",
			response:      goodResponse(),
			expectedBody:  []byte("response body"),
			expectedError: "",
		},
		{
			name:          "Test failed response",
			response:      badResponse(),
			expectedBody:  nil,
			expectedError: "error message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := SecretDataResponse(tc.response)

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				bodyBytes, err := io.ReadAll(body)
				require.NoError(t, err)
				require.NoError(t, body.Close())

				assert.Equal(t, tc.expectedBody, bodyBytes)
			}
		})
	}
}

func TestEmptyResponse(t *testing.T) {
	testCases := []struct {
		name          string
		response      *http.Response
		expectedBody  []byte
		expectedError string
	}{
		{
			name:          "Test successful response",
			response:      goodResponse(), // EmptyResponse ignores the body
			expectedBody:  []byte("response body"),
			expectedError: "",
		},
		{
			name:          "Test failed response",
			response:      badResponse(),
			expectedBody:  nil,
			expectedError: "error message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := EmptyResponse(tc.response)

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type testJSONStruct struct {
	Name string
}

func TestJSONResponse(t *testing.T) {
	testCases := []struct {
		name               string
		response           *http.Response
		expectedResult     testJSONStruct
		expectedError      string
		isDryRunPolicyLoad bool
	}{
		{
			name: "Test successful response",
			response: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"name":"John","age":30}`)),
				Request:    goodRequest(),
			},
			expectedResult: testJSONStruct{Name: "John"},
			expectedError:  "",
		},
		{
			name: "Test successful response with DryRunPolicyJSONResponse",
			response: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"name":"John","age":30}`)),
				Request:    goodRequest(),
			},
			expectedResult:     testJSONStruct{Name: "John"},
			expectedError:      "",
			isDryRunPolicyLoad: true,
		},
		{
			name:           "Test failed response",
			response:       badResponse(),
			expectedResult: testJSONStruct{},
			expectedError:  "error message",
		},
		{
			name:               "Test failed response with DryRunPolicyJSONResponse",
			response:           badResponse(),
			expectedResult:     testJSONStruct{},
			expectedError:      "error message",
			isDryRunPolicyLoad: true,
		},
		{
			name: "Test 422 response code",
			response: &http.Response{
				StatusCode: 422,
				Body:       io.NopCloser(bytes.NewBufferString("error message")),
				Request:    goodRequest(),
			},
			expectedResult: testJSONStruct{},
			expectedError:  "error message",
		},
		{
			name: "Test 422 response code with DryRunPolicyJSONResponse",
			response: &http.Response{
				StatusCode: 422,
				Body:       io.NopCloser(bytes.NewBufferString(`{"name":"John","age":30}`)),
				Request:    goodRequest(),
			},
			expectedResult:     testJSONStruct{Name: "John"},
			expectedError:      "",
			isDryRunPolicyLoad: true,
		},
		{
			name: "Error reading response body",
			response: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(errorReader{}),
				Request:    goodRequest(),
			},
			expectedResult: testJSONStruct{},
			expectedError:  "test read error",
		},
		{
			name: "Error reading response body with DryRunPolicyJSONResponse",
			response: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(errorReader{}),
				Request:    goodRequest(),
			},
			expectedResult:     testJSONStruct{},
			expectedError:      "test read error",
			isDryRunPolicyLoad: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var result testJSONStruct
			var err error

			if !tc.isDryRunPolicyLoad {
				err = JSONResponse(tc.response, &result)
			} else {
				err = DryRunPolicyJSONResponse(tc.response, &result)
			}

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, result, tc.expectedResult)
			}
		})
	}
}

func goodRequest() *http.Request {
	return &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
		},
		Header: http.Header{
			"Authorization": []string{"Bearer super_secret_access_token"},
			"Content-Type":  []string{"application/json"},
		},
	}
}

func goodResponse() *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString("response body")),
		Request:    goodRequest(),
	}
}

func badResponse() *http.Response {
	return &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(bytes.NewBufferString("error message")),
		Request:    goodRequest(),
	}
}

// errorReader is an io.Reader that always returns an error
// for testing purposes
type errorReader struct{}

func (e errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("test read error")
}
