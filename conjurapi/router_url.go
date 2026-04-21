package conjurapi

import (
	"fmt"
	"net/url"
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
//
// Note:
//   - Each suffix is quoted so literal dots are not treated as wildcards.
//   - Suffixes are wrapped in a group so the prefix applies to all possible suffixes.
//   - Pattern is end anchored, but not start anchored. The prefix and suffix match
//     must be at the end of the hostname, but there may be additional subdomains
//     before the prefix.
var ConjurCloudRegexp = func() *regexp.Regexp {
	quoted := make([]string, len(ConjurCloudSuffixes))
	for i, s := range ConjurCloudSuffixes {
		quoted[i] = regexp.QuoteMeta(s)
	}
	return regexp.MustCompile(`(\.secretsmgr|-secretsmanager)(` + strings.Join(quoted, "|") + `)$`)
}()

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
		logging.ApiLog.Info("Detected Idira Secrets Manager, SaaS URL, adding '/api' prefix")
		return url + "/api"
	}

	return url
}

func isConjurCloudURL(baseURL string) bool {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" {
		return false
	}
	return ConjurCloudRegexp.MatchString(strings.ToLower(parsed.Hostname()))
}
