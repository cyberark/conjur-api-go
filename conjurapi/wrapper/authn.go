package wrapper

import (
	"fmt"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"net/http"
	"net/url"
	"strings"
)

func AuthenticateRequest(applianceURL, account string, loginPair authn.LoginPair) (*http.Request, error) {
	authenticateUrl := fmt.Sprintf("%s/authn/%s/%s/authenticate", applianceURL, account, url.QueryEscape(loginPair.Login))

	req, err := http.NewRequest("POST", authenticateUrl, strings.NewReader(loginPair.APIKey))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	return req, nil
}

func AuthenticateResponse(resp *http.Response) ([]byte, error) {
	return response.SecretDataResponse(resp)
}
