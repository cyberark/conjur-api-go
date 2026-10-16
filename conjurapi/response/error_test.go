package response

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConjurError(t *testing.T) {
	testCases := []struct {
		name     string
		resp     *http.Response
		expected *ConjurError
	}{
		{
			name: "simple error",
			resp: &http.Response{
				StatusCode: 404,
				Status:     "Not Found",
				Body:       io.NopCloser(strings.NewReader(`{"error": {"message": "Not Found"}}`)),
			},
			expected: &ConjurError{
				Code:    404,
				Message: "Not Found",
				Details: &ConjurErrorDetails{
					Message: "Not Found",
				},
			},
		},
		{
			name: "Conjur error with details",
			resp: &http.Response{
				StatusCode: 404,
				Status:     "Not Found",
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"not_found","message":"CONJ00076E Variable conjur:variable:some_var is empty or not found."}}`)),
			},
			expected: &ConjurError{
				Code:    404,
				Message: "Not Found",
				Details: &ConjurErrorDetails{
					Message: "CONJ00076E Variable conjur:variable:some_var is empty or not found.",
					Code:    "not_found",
				},
			},
		},
		{
			name: "empty body",
			resp: &http.Response{
				StatusCode: 403,
				Status:     "Forbidden",
				Body:       io.NopCloser(strings.NewReader("")),
			},
			expected: &ConjurError{
				Code:    403,
				Message: "Forbidden",
			},
		},
		{
			name: "invalid JSON",
			resp: &http.Response{
				StatusCode: 403,
				Status:     "Forbidden",
				Body:       io.NopCloser(strings.NewReader(`not json`)),
			},
			expected: &ConjurError{
				Code:    403,
				Message: "Forbidden",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewConjurError(tc.resp)

			require.Error(t, err)
			cerr, ok := err.(*ConjurError)
			require.True(t, ok, "expected error to be a *ConjurError, got %T", err)

			assert.EqualValues(t, tc.expected.Code, cerr.Code)
		})
	}

	t.Run("errors.As extracts ConjurError.Code", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 404,
			Status:     "Not Found",
			Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"not found"}}`)),
		}
		err := NewConjurError(resp)
		require.Error(t, err)

		var conjurErr *ConjurError
		require.True(t, errors.As(err, &conjurErr), "expected errors.As to find *ConjurError")
		assert.Equal(t, 404, conjurErr.Code)
	})

	t.Run("error reading body", func(t *testing.T) {
		resp := &http.Response{
			Body: io.NopCloser(&errorReader{}),
		}

		err := NewConjurError(resp)
		require.Error(t, err)
		assert.EqualError(t, err, "test read error")
	})
}

func TestConjurError_Error(t *testing.T) {
	testCases := []struct {
		name      string
		conjurErr *ConjurError
		expected  string
	}{
		{
			name: "with message and details",
			conjurErr: &ConjurError{
				Code:    404,
				Message: "Not Found",
				Details: &ConjurErrorDetails{
					Message: "CONJ00076E Variable conjur:variable:some_var is empty or not found",
					Code:    "not_found",
				},
			},
			expected: "Not Found. CONJ00076E Variable conjur:variable:some_var is empty or not found.",
		},
		{
			name: "with message only",
			conjurErr: &ConjurError{
				Code:    403,
				Message: "Forbidden",
			},
			expected: "Forbidden",
		},
		{
			name: "with details only",
			conjurErr: &ConjurError{
				Code: 404,
				Details: &ConjurErrorDetails{
					Message: "CONJ00076E Variable conjur:variable:some_var is empty or not found",
					Code:    "not_found",
				},
			},
			expected: "CONJ00076E Variable conjur:variable:some_var is empty or not found.",
		},
		{
			name: "with empty message and details",
			conjurErr: &ConjurError{
				Code:    500,
				Message: "",
				Details: &ConjurErrorDetails{
					Message: "",
					Code:    "",
				},
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.conjurErr.Error()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestNewConjurError_BodyShapes(t *testing.T) {
	validationFailed := `{"error":{"code":"validation_failed","message":"value is not present","details":[{"code":"validation_failed","target":"value","message":"is not present"}]}}`

	testCases := []struct {
		name        string
		status      string
		code        int
		body        string
		wantError   string
		wantDetails any
	}{
		{
			name:      "validation error with a details list",
			status:    "422 Unprocessable Entity",
			code:      422,
			body:      validationFailed,
			wantError: "422 Unprocessable Entity. value is not present.",
			wantDetails: []any{map[string]any{
				"code": "validation_failed", "target": "value", "message": "is not present",
			}},
		},
		{
			name:        "details object",
			status:      "404 Not Found",
			code:        404,
			body:        `{"error":{"code":"not_found","message":"Group 'data/g' not found","details":{"code":"not_found","target":"id","message":"data/g"}}}`,
			wantError:   "404 Not Found. Group 'data/g' not found.",
			wantDetails: map[string]any{"code": "not_found", "target": "id", "message": "data/g"},
		},
		{
			name:      "no details",
			status:    "422 Unprocessable Entity",
			code:      422,
			body:      `{"error":{"code":"unprocessable_entity","message":"Cannot have more than 20 annotations"}}`,
			wantError: "422 Unprocessable Entity. Cannot have more than 20 annotations.",
		},
		{
			name:      "flat body",
			status:    "404 Not Found",
			code:      404,
			body:      `{"code":"404","message":"Branch 'data/b' not found"}`,
			wantError: `{"code":"404","message":"Branch 'data/b' not found"}`,
		},
		{
			name:      "string error",
			status:    "401 Unauthorized",
			code:      401,
			body:      `{"error":"invalid credentials"}`,
			wantError: `{"error":"invalid credentials"}`,
		},
		{
			name:      "plain text",
			status:    "502 Bad Gateway",
			code:      502,
			body:      "Bad Gateway",
			wantError: "Bad Gateway",
		},
		{
			name:      "empty body",
			status:    "403 Forbidden",
			code:      403,
			body:      "",
			wantError: "403 Forbidden",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := NewConjurError(&http.Response{
				StatusCode: tc.code,
				Status:     tc.status,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			})

			var cerr *ConjurError
			require.True(t, errors.As(err, &cerr))
			assert.Equal(t, tc.code, cerr.Code)
			assert.Equal(t, tc.wantError, err.Error())
			if tc.wantDetails != nil {
				require.NotNil(t, cerr.Details)
				assert.Equal(t, tc.wantDetails, cerr.Details.Details)
			}
		})
	}
}
