package conjurapi

import (
	"fmt"
	"path"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

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

	// If using '*.secretsmgr.cyberark.cloud', add '/api'
	if strings.HasSuffix(url, ".secretsmgr.cyberark.cloud") {
		logging.ApiLog.Debugf("Detected Conjur Cloud URL, adding '/api' prefix")
		return url + "/api"
	}

	return url
}
