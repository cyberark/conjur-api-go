package httputil

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// trackingBody records whether it was closed, so a test can tell whether
// DrainClose actually drained its content instead of just closing it (the
// underlying io.Reader is checked separately for EOF).
type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func TestDrainClose(t *testing.T) {
	t.Run("drains and closes a response body", func(t *testing.T) {
		body := &trackingBody{Reader: strings.NewReader("unread body content")}
		resp := &http.Response{Body: body}

		DrainClose(resp)

		assert.True(t, body.closed, "expected body to be closed")

		n, err := body.Reader.Read(make([]byte, 1))
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err, "expected body to be fully drained before closing")
	})

	t.Run("nil response is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() { DrainClose(nil) })
	})

	t.Run("nil body is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() { DrainClose(&http.Response{Body: nil}) })
	})

	t.Run("already-drained body does not panic on a second call", func(t *testing.T) {
		body := &trackingBody{Reader: strings.NewReader("content")}
		resp := &http.Response{Body: body}

		DrainClose(resp)
		assert.NotPanics(t, func() { DrainClose(resp) })
	})
}
