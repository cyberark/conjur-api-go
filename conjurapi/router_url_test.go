package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_makeRouterURL(t *testing.T) {
	t.Run("makeRouterURL removes extra '/'s between base and components", func(t *testing.T) {
		urlWithPath := routerURL("http://some.host/some/path")
		urlWithSubPath := routerURL("http://some.host/path/to/something/subpath/to/another")

		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host", "some/path"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host/", "//some/path"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host/", "some//path"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host/", "some/path//"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host", "//some/path"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host", "some//path"))
		assert.Equal(t, urlWithPath, makeRouterURL("http://some.host", "some/path//"))
		assert.Equal(t, urlWithSubPath, makeRouterURL("http://some.host/path/to/something/", "//subpath//to//another"))
	})

	t.Run("makeRouterURL handles Secrets Manager SaaS base URL", func(t *testing.T) {
		cloudUrlWithPath := routerURL("http://some.host.secretsmgr.cyberark.cloud/api/some/path")
		cloudUrlWithSubPath := routerURL("http://some.host.secretsmgr.cyberark.cloud/api/some/path/subpath/to/another")

		t.Run("when '/api' prefix is not provided", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithPath, makeRouterURL("http://some.host.secretsmgr.cyberark.cloud", "some/path"))
		})

		t.Run("when '/api' prefix is provided", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithPath, makeRouterURL("http://some.host.secretsmgr.cyberark.cloud/api", "some/path"))
		})

		t.Run("when adding subpaths", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithSubPath, makeRouterURL("http://some.host.secretsmgr.cyberark.cloud/api/some/path/", "subpath/to/another"))
		})
	})
}
