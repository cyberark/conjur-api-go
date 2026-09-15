package conjurapi

import (
	"errors"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// IsConflict reports whether err represents an HTTP 409 Conflict returned by a
// V2 endpoint — for example a duplicate-create. Callers should use this
// predicate rather than substring-matching the error message, since the message
// text is not part of the API contract.
//
//	_, err := client.V2().CreateBranch(branch)
//	if conjurapi.IsConflict(err) {
//	    // branch already exists
//	}
func IsConflict(err error) bool {
	return hasConjurErrorCode(err, http.StatusConflict)
}

// IsNotFound reports whether err represents an HTTP 404 Not Found returned by a
// V2 endpoint — for example deleting or fetching a resource that does not exist.
// Callers should use this predicate rather than substring-matching the error
// message.
func IsNotFound(err error) bool {
	return hasConjurErrorCode(err, http.StatusNotFound)
}

// IsForbidden reports whether err represents an HTTP 403 Forbidden returned by a
// V2 endpoint — for example deleting a branch the caller lacks update rights on,
// or a cascade delete the server refuses.
func IsForbidden(err error) bool {
	return hasConjurErrorCode(err, http.StatusForbidden)
}

// hasConjurErrorCode reports whether err (or an error it wraps) is a
// *response.ConjurError carrying the given HTTP status code.
func hasConjurErrorCode(err error, code int) bool {
	var conjurErr *response.ConjurError
	if errors.As(err, &conjurErr) {
		return conjurErr.Code == code
	}
	return false
}
