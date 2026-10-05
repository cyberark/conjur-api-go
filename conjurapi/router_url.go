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
	if len(urlBase) > len(base) {
		logging.ApiLog.Info("Detected Idira Secrets Manager, SaaS URL, adding '/api' prefix")
	}
	urlPath := path.Join(components...)
	urlPath = strings.TrimPrefix(urlPath, "/")
	return routerURL(urlBase + "/" + urlPath)
}

// escapePathSegments turns each caller-supplied value into exactly one path
// segment for makeRouterURL to join. Characters that could be misparsed as
// URL delimiters - ' ', '?', '#', '%', '/' among them - are percent-encoded,
// so a value containing "/" collapses into one segment instead of
// introducing separators of its own.
//
// Empty, "." and ".." values are rejected rather than escaped, since
// url.PathEscape leaves all three alone and path.Join inside makeRouterURL
// would then collapse or resolve them - letting caller input address a
// different resource, or escape the URL prefix entirely. Those strings as
// substrings are safe, since the surrounding "/" is encoded and path.Join
// sees no separator to act on.
//
// what names the offending input in the error message, e.g. "Workload URL".
func escapePathSegments(what string, segments []string) ([]string, error) {
	escaped := make([]string, len(segments))
	for i, s := range segments {
		if s == "" || s == "." || s == ".." {
			return nil, fmt.Errorf("%s components must not be empty, \".\", or \"..\"", what)
		}
		escaped[i] = url.PathEscape(s)
	}
	return escaped, nil
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

// normalizeBaseURL returns baseURL's API base URL, trimmed of its trailing
// slash. A caller that needs to know whether this added the SaaS '/api'
// prefix (see makeRouterURL) can tell from the result growing longer -
// trimming the trailing slash alone never does.
func normalizeBaseURL(baseURL string) string {
	url := strings.TrimSuffix(baseURL, "/")
	if isConjurCloudURL(url) && !strings.Contains(url, "/api") {
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
