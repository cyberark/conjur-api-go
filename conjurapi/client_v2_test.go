package conjurapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validationFailedBody is the 422 the server sends for a model validation
// error, captured from SaaS for a whitespace-only annotation value.
const validationFailedBody = `{"error":{"code":"validation_failed","message":"value is not present","details":[{"code":"validation_failed","target":"value","message":"is not present"}]}}`

// v2HelperCalls exercises each submit helper through a ClientV2 method.
func v2HelperCalls(c *ClientV2) map[string]func() error {
	annotations := map[string]string{"space": " "}
	return map[string]func() error{
		"submitAndUnmarshal": func() error {
			_, err := c.CreateGroup(Group{Name: "g", Branch: "data", Annotations: annotations})
			return err
		},
		"submitAndReadData": func() error {
			_, err := c.UpdateBranch(Branch{Name: "data/b", Annotations: annotations})
			return err
		},
		"submitAndEmpty": func() error {
			return c.DeleteGroup("data/g")
		},
	}
}

func TestV2Helpers_ValidationErrorWithDetailsList(t *testing.T) {
	ts, client := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(validationFailedBody))
	})
	defer ts.Close()

	for helper, call := range v2HelperCalls(client.V2()) {
		t.Run(helper, func(t *testing.T) {
			err := call()
			var cerr *response.ConjurError
			require.True(t, errors.As(err, &cerr), "want *response.ConjurError, got %T", err)
			assert.Equal(t, http.StatusUnprocessableEntity, cerr.Code)
			assert.Equal(t, "422 Unprocessable Entity. value is not present.", err.Error())
		})
	}
}

func TestV2Authenticators_ValidationErrorWithDetailsList(t *testing.T) {
	ts, client := newSaaSGroupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(validationFailedBody))
	})
	defer ts.Close()
	c := client.V2()
	want := "422 Unprocessable Entity. value is not present."

	created, err := c.CreateAuthenticator(&AuthenticatorBase{Type: "jwt", Name: "a"})
	assert.Nil(t, created)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	got, err := c.GetAuthenticator("jwt", "a")
	assert.Nil(t, got)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	updated, err := c.UpdateAuthenticator("jwt", "a", false)
	assert.Nil(t, updated)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	list, err := c.ListAuthenticators()
	assert.Nil(t, list)
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	err = c.DeleteAuthenticator("jwt", "a")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())
}
