package wrapper_v4

import (
	"net/url"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func RetrieveSecretRequest(applianceURL, variableIdentifier string) (*http.Request, error) {
	return http.NewRequest(
		"GET",
		VariableURL(applianceURL, variableIdentifier),
		nil,
	)
}

func RetrieveSecretResponse(resp *http.Response) ([]byte, error) {
	return response.SecretDataResponse(resp)
}

func VariableURL(applianceURL, variableIdentifier string) string {
	return fmt.Sprintf("%s/variables/%s/value", applianceURL, url.QueryEscape(variableIdentifier))
}
