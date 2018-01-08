package wrapper

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

func RetrieveSecretRequest(applianceURL, variableId string) (*http.Request, error) {
	return http.NewRequest(
		"GET",
		VariableURL(applianceURL, variableId),
		nil,
	)
}

func AddSecretRequest(applianceURL, variableId, secretValue string) (*http.Request, error) {
	return http.NewRequest(
		"POST",
		VariableURL(applianceURL, variableId),
		strings.NewReader(secretValue),
	)
}

func RetrieveSecretResponse(resp *http.Response) ([]byte, error) {
	return response.SecretDataResponse(resp)
}

func AddSecretResponse(resp *http.Response) error {
	return response.EmptyResponse(resp)
}

func VariableURL(applianceURL, variableId string) string {
	tokens := strings.SplitN(variableId, ":", 3)
	return fmt.Sprintf("%s/secrets/%s/%s/%s", applianceURL, tokens[0], tokens[1], url.QueryEscape(tokens[2]))
}
