package wrapper

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func LoadPolicyRequest(applianceURL string, policyId string, policy io.Reader) (*http.Request, error) {
	tokens := strings.SplitN(policyId, ":", 3)
	policyUrl := fmt.Sprintf("%s/policies/%s/%s/%s", applianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]))

	return http.NewRequest(
		"PUT",
		policyUrl,
		policy,
	)
}

func LoadPolicyResponse(resp *http.Response) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	return obj, response.JSONResponse(resp, &obj)
}
