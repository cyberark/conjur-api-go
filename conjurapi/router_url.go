package conjurapi

import (
	"fmt"
	"path"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

var ConjurCloudSuffixes = []string{
	".secretsmgr.cyberark.cloud",
	".secretsmgr.integration-cyberark.cloud",
}

type routerURL string

func makeRouterURL(base string, components ...string) routerURL {
	urlBase := normalizeBaseURL(base)
	urlPath := path.Join(components...)
	urlPath = strings.TrimPrefix(urlPath, "/")
	return routerURL(urlBase + "/" + urlPath)
}

func (u routerURL) withFormattedQuery(queryFormat string, queryArgs ...interface{}) routerURL {
	query := fmt.Sprintf(queryFormat, queryArgs...)
	return routerURL(strings.Join([]string{string(u), query}, "?"))
}

func (u routerURL) withQuery(query string) routerURL {
	return routerURL(strings.Join([]string{string(u), query}, "?"))
}

func (u routerURL) String() string {
	return string(u)
}

func normalizeBaseURL(baseURL string) string {
	url := strings.TrimSuffix(baseURL, "/")

	if isConjurCloudURL(url) && !strings.HasSuffix(url, "/api") {
		logging.ApiLog.Info("Detected Conjur Cloud URL, adding '/api' prefix")
		return url + "/api"
	}

	return url
}

func isConjurCloudURL(baseURL string) bool {
	url := strings.TrimSuffix(baseURL, "/")

	for _, suffix := range ConjurCloudSuffixes {
		if strings.HasSuffix(url, suffix) || strings.HasSuffix(url, suffix+"/api") {
			return true
		}
	}

	return false
}
