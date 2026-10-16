package response

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// ConjurError is the error type returned when the Conjur server responds with a
// non-2xx status. It preserves the HTTP status code so callers can distinguish
// error conditions without relying on error-message text:
//
//	var conjurErr *ConjurError
//	if errors.As(err, &conjurErr) {
//	    switch conjurErr.Code {
//	    case 404:
//	        // Resource or authenticator webservice not found
//	    case 403:
//	        // Access denied
//	    }
//	}
type ConjurError struct {
	Code    int
	Message string
	Details *ConjurErrorDetails `json:"error"`
}

type ConjurErrorDetails struct {
	Message string
	Code    string
	Target  string
	// Details holds the error body's "details" as decoded JSON: an object for
	// not-found and conflict errors, a list for validation errors.
	Details any
}

func NewConjurError(resp *http.Response) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	cerr := ConjurError{}
	cerr.Code = resp.StatusCode
	err = json.Unmarshal(body, &cerr)
	if err != nil {
		cerr.Message = strings.TrimSpace(string(body))
	}

	// If the body's empty, use the HTTP status as the message
	if cerr.Message == "" {
		cerr.Message = resp.Status
	}

	return &cerr
}

func (cerr *ConjurError) Error() string {
	logging.ApiLog.Debugf("cerr.Details: %+v, cerr.Message: %+v\n", cerr.Details, cerr.Message)

	var b strings.Builder

	hasMessage := cerr.Message != ""
	hasDetails := cerr.Details != nil && cerr.Details.Message != ""

	if hasMessage {
		b.WriteString(cerr.Message)

		// If there's both a message and details, separate them with a period and space
		if hasDetails {
			b.WriteString(". ")
		}
	}

	if hasDetails {
		b.WriteString(cerr.Details.Message + ".")
	}

	return b.String()
}
