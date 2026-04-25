package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isConjurCloudURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		// True positives — .secretsmgr prefix with each known suffix
		{"secretsmgr + .cyberark.cloud", "https://tenant.secretsmgr.cyberark.cloud", true},
		{"secretsmgr + .integration-cyberark.cloud", "https://tenant.secretsmgr.integration-cyberark.cloud", true},
		{"secretsmgr + .test-cyberark.cloud", "https://tenant.secretsmgr.test-cyberark.cloud", true},
		{"secretsmgr + .dev-cyberark.cloud", "https://tenant.secretsmgr.dev-cyberark.cloud", true},
		{"secretsmgr + .cyberark-everest-integdev.cloud", "https://tenant.secretsmgr.cyberark-everest-integdev.cloud", true},
		{"secretsmgr + .cyberark-everest-pre-prod.cloud", "https://tenant.secretsmgr.cyberark-everest-pre-prod.cloud", true},
		{"secretsmgr + .sandbox-cyberark.cloud", "https://tenant.secretsmgr.sandbox-cyberark.cloud", true},
		{"secretsmgr + .pt-cyberark.cloud", "https://tenant.secretsmgr.pt-cyberark.cloud", true},

		// True positives — -secretsmanager prefix with each known suffix
		{"secretsmanager + .cyberark.cloud", "https://tenant-secretsmanager.cyberark.cloud", true},
		{"secretsmanager + .integration-cyberark.cloud", "https://tenant-secretsmanager.integration-cyberark.cloud", true},
		{"secretsmanager + .test-cyberark.cloud", "https://tenant-secretsmanager.test-cyberark.cloud", true},
		{"secretsmanager + .dev-cyberark.cloud", "https://tenant-secretsmanager.dev-cyberark.cloud", true},
		{"secretsmanager + .cyberark-everest-integdev.cloud", "https://tenant-secretsmanager.cyberark-everest-integdev.cloud", true},
		{"secretsmanager + .cyberark-everest-pre-prod.cloud", "https://tenant-secretsmanager.cyberark-everest-pre-prod.cloud", true},
		{"secretsmanager + .sandbox-cyberark.cloud", "https://tenant-secretsmanager.sandbox-cyberark.cloud", true},
		{"secretsmanager + .pt-cyberark.cloud", "https://tenant-secretsmanager.pt-cyberark.cloud", true},

		// True negatives — enterprise / on-prem appliances
		{"enterprise appliance hostname", "https://my-conjur.example.com", false},
		{"localhost", "http://localhost", false},
		{"empty string", "", false},

		// Bug 1 regression — suffix present but required prefix missing; previously matched
		// due to operator precedence making each suffix after the first a bare alternation.
		{"bare .integration-cyberark.cloud (no prefix)", "https://anything.integration-cyberark.cloud", false},
		{"bare .test-cyberark.cloud (no prefix)", "https://anything.test-cyberark.cloud", false},
		{"bare .dev-cyberark.cloud (no prefix)", "https://anything.dev-cyberark.cloud", false},
		{"bare .cyberark-everest-integdev.cloud (no prefix)", "https://anything.cyberark-everest-integdev.cloud", false},
		{"bare .cyberark-everest-pre-prod.cloud (no prefix)", "https://anything.cyberark-everest-pre-prod.cloud", false},
		{"bare .sandbox-cyberark.cloud (no prefix)", "https://anything.sandbox-cyberark.cloud", false},
		{"bare .pt-cyberark.cloud (no prefix)", "https://anything.pt-cyberark.cloud", false},

		// Bug 2 regression — dots in suffix replaced by arbitrary characters; previously matched
		// because unescaped '.' in the pattern acts as a wildcard.
		{"dot replaced by char in suffix (.cyberark.cloud)", "https://tenant.secretsmgrXcyberarkYcloud.com", false},
		{"dot replaced by char in suffix (.sandbox-cyberark.cloud)", "https://tenant.secretsmgrXsandbox-cyberarkYcloud.com", false},

		// Cloud pattern in path or query must not match — only the hostname is tested.
		{"cloud pattern in query string", "https://enterprise.internal?x=tenant.secretsmgr.cyberark.cloud", false},
		{"cloud pattern in path", "https://enterprise.internal/tenant.secretsmgr.cyberark.cloud/something", false},
		{"cloud pattern in fragment", "https://enterprise.internal#tenant.secretsmgr.cyberark.cloud", false},

		// Subdomain-wrapping attack — cloud pattern present as sub-domain of attacker host.
		{"cloud suffix as subdomain of attacker host", "https://tenant.secretsmgr.cyberark.cloud.attacker.com", false},
		{"cloud suffix as subdomain of attacker host (non-first suffix)", "https://tenant.secretsmgr.sandbox-cyberark.cloud.attacker.com", false},

		// HTTP scheme must not match; only HTTPS is valid for Conjur Cloud URLs.
		{"http scheme with valid cloud pattern", "http://tenant.secretsmgr.cyberark.cloud", false},

		// DNS names are case insensitive
		{"uppercase letters in hostname", "https://TENANT.SECRETSMGR.CYBERARK.CLOUD", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isConjurCloudURL(tt.url))
		})
	}
}

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
		cloudUrlWithPath := routerURL("https://some.host.secretsmgr.cyberark.cloud/api/some/path")
		cloudUrlWithSubPath := routerURL("https://some.host.secretsmgr.cyberark.cloud/api/some/path/subpath/to/another")

		t.Run("when '/api' prefix is not provided", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithPath, makeRouterURL("https://some.host.secretsmgr.cyberark.cloud", "some/path"))
		})

		t.Run("when '/api' prefix is provided", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithPath, makeRouterURL("https://some.host.secretsmgr.cyberark.cloud/api", "some/path"))
		})

		t.Run("when adding subpaths", func(t *testing.T) {
			assert.Equal(t, cloudUrlWithSubPath, makeRouterURL("https://some.host.secretsmgr.cyberark.cloud/api/some/path/", "subpath/to/another"))
		})
	})
}
