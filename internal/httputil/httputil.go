// Package httputil provides small HTTP helpers shared across this module's
// packages.
package httputil

import (
	"io"
	"net/http"
)

// DrainClose drains a response body so the underlying connection can be
// reused, then closes it.
func DrainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
