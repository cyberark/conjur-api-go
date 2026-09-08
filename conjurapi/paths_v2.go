package conjurapi

import (
	"net/url"
	"strings"
)

// escapeIdentifierPath percent-escapes each slash-separated segment of a
// resource identifier while preserving the slashes themselves, so an identifier
// like "data/test/my host" becomes "data/test/my%20host". This suits v2 routes
// whose trailing parameter is a "*glob" that captures slashes (group member
// ids, permission role ids, annotation names, safe names, …): the path
// structure is kept while URL-significant characters in each segment are made
// safe.
func escapeIdentifierPath(identifier string) string {
	segments := strings.Split(identifier, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}
