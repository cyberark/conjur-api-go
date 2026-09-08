package conjurapi

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
)

func TestErrorPredicates(t *testing.T) {
	conflict := &response.ConjurError{Code: http.StatusConflict}
	notFound := &response.ConjurError{Code: http.StatusNotFound}
	forbidden := &response.ConjurError{Code: http.StatusForbidden}

	assert.True(t, IsConflict(conflict))
	assert.False(t, IsNotFound(conflict))
	assert.False(t, IsForbidden(conflict))

	assert.True(t, IsNotFound(notFound))
	assert.True(t, IsForbidden(forbidden))

	// A wrapped ConjurError is still classified (errors.As unwraps).
	wrapped := fmt.Errorf("create failed: %w", conflict)
	assert.True(t, IsConflict(wrapped))

	// nil and non-ConjurError errors are never matched.
	assert.False(t, IsConflict(nil))
	assert.False(t, IsNotFound(nil))
	assert.False(t, IsForbidden(nil))
	plain := fmt.Errorf("409 conflict not found forbidden")
	assert.False(t, IsConflict(plain))
	assert.False(t, IsNotFound(plain))
	assert.False(t, IsForbidden(plain))
}

func TestEscapeIdentifierPath(t *testing.T) {
	// Slashes are preserved (they map to a route's *glob); other
	// URL-significant characters are percent-escaped per segment.
	assert.Equal(t, "data/test/bob", escapeIdentifierPath("data/test/bob"))
	assert.Equal(t, "data/test/my%20host", escapeIdentifierPath("data/test/my host"))
	assert.Equal(t, "a%23b", escapeIdentifierPath("a#b"))
	assert.Equal(t, "", escapeIdentifierPath(""))
	assert.Equal(t, "a/b%20c/d", escapeIdentifierPath("a/b c/d"))
}
