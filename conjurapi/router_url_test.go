package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_makeRouterURL(t *testing.T) {
	t.Run("makeRouterURL removes extra '/'s between base and components", func(t *testing.T) {
		assert.Equal(t, makeRouterURL("http://some.host", "some/path"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host/", "//some/path"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host/", "some//path"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host/", "some/path//"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host", "//some/path"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host", "some//path"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host", "some/path//"), routerURL("http://some.host/some/path"))
		assert.Equal(t, makeRouterURL("http://some.host/path/to/something/", "//subpath//to//another"), routerURL("http://some.host/path/to/something/subpath/to/another"))

	})
}
