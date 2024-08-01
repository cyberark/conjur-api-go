package response

import (
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
			expected: "Forbidden. ",
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
