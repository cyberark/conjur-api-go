package conjurapi

import (
	"fmt"
	"strings"
	"path"
)

type routerURL string

func makeRouterURL(base string, components ...string) routerURL {
	urlBase := strings.TrimSuffix(base, "/")
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
