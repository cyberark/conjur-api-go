package conjurapi

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// ConjurCloudSuffixes is a list of all possible Secrets Manager SaaS URL suffixes.
var ConjurCloudSuffixes = []string{
	".cyberark.cloud",
	".integration-cyberark.cloud",
	".test-cyberark.cloud",
	".dev-cyberark.cloud",
	".cyberark-everest-integdev.cloud",
	".cyberark-everest-pre-prod.cloud",
	".sandbox-cyberark.cloud",
	".pt-cyberark.cloud",
}

// ConjurCloudRegexp is a regex pattern that matches all possible Secrets Manager SaaS URLs.
var ConjurCloudRegexp = regexp.MustCompile("(\\.secretsmgr|-secretsmanager)" + strings.Join(ConjurCloudSuffixes, "|"))

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
	if isConjurCloudURL(url) && !strings.Contains(url, "/api") {
		logging.ApiLog.Info("Detected Secrets Manager SaaS URL, adding '/api' prefix")
		return url + "/api"
	}

	return url
}

func isConjurCloudURL(baseURL string) bool {
	return ConjurCloudRegexp.MatchString(baseURL)
}
