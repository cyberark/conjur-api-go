package conjurapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type EnterpriseInfoResponse struct {
	Release        string                           `json:"release"`
	Version        string                           `json:"version"`
	Services       map[string]EnterpriseInfoService `json:"services"`
	Container      string                           `json:"container"`
	Role           string                           `json:"role"`
	Configuration  interface{}                      `json:"configuration"`
	Authenticators interface{}                      `json:"authenticators"`
	FipsMode       string                           `json:"fips_mode"`
	FeatureFlags   interface{}                      `json:"feature_flags"`
}

type EnterpriseInfoService struct {
	Desired     string `json:"desired"`
	Status      string `json:"status"`
	Err         string `json:"err"`
	Description string `json:"description"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
}

// ServerVersion retrieves the Conjur server version, either from the '/info' endpoint in Secrets Manager Self-Hosted,
// or from the root endpoint in Conjur OSS. The version returned corresponds to the Conjur OSS version,
// which in Conjur Enterprise is the version of the 'possum' service.
func (c *Client) ServerVersion() (string, error) {
	if isConjurCloudURL(c.config.ApplianceURL) {
		return "", errors.New("Unable to retrieve server version: not supported in Secrets Manager SaaS")
	}

	info, err := c.EnterpriseServerInfo()
	if err == nil {
		// Return the version of the 'possum' service, which corresponds to the Conjur OSS version
		return info.Services["possum"].Version, nil
	}

	version, err := c.ServerVersionFromRoot()
	if err == nil {
		return version, nil
	}

	return "", fmt.Errorf("failed to retrieve server version: %s", err)
}

// EnterpriseServerInfo retrieves the server information from the '/info' endpoint.
// This is only available in Conjur Enterprise and will fail with a 404 error in Conjur OSS.
func (c *Client) EnterpriseServerInfo() (*EnterpriseInfoResponse, error) {
	if isConjurCloudURL(c.config.ApplianceURL) {
		return nil, errors.New("Unable to retrieve server info: not supported in Secrets Manager SaaS")
	}

	req, err := c.ServerInfoRequest()
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	// Handle 404 or 401 response, which indicates that the '/info' endpoint is not available (eg. in Conjur OSS)
	if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized) {
		return nil, fmt.Errorf("404 Not Found: Are you using Conjur Enterprise?")
	}

	// Handle any other errors
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server info: %s", err)
	}

	infoResponse := EnterpriseInfoResponse{}
	return &infoResponse, response.JSONResponse(resp, &infoResponse)
}

// ServerVersionFromRoot retrieves the server version from the root endpoint.
// This is a fallback method in case the '/info' endpoint is not available (such as in Conjur OSS).
// In older versions of Conjur, the version was only available in an HTML response, and
// this method will parse it from there.
// In newer Conjur versions, the version is available in a JSON response.
func (c *Client) ServerVersionFromRoot() (string, error) {
	if isConjurCloudURL(c.config.ApplianceURL) {
		return "", errors.New("Unable to retrieve server version: not supported in Secrets Manager SaaS")
	}

	req, err := c.RootRequest()
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	body, err := response.DataResponse(resp)
	if err != nil {
		return "", err
	}

	serverVersion, err := parseVersionFromRoot(resp, body)
	if err != nil {
		return "", err
	}

	return serverVersion, nil
}

func parseVersionFromRoot(rootResponse *http.Response, body []byte) (string, error) {
	if strings.Contains(rootResponse.Header.Get("content-type"), "application/json") {
		return parseVersionFromJSON(body)
	}

	return parseVersionFromHTML(string(body))
}

func parseVersionFromJSON(jsonContent []byte) (string, error) {
	// Parse the body as JSON and look for the version field
	var result map[string]interface{}
	if err := json.Unmarshal(jsonContent, &result); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %s", err)
	}

	if version, ok := result["version"].(string); ok {
		return version, nil
	}

	return "", fmt.Errorf("version field not found")
}

func parseVersionFromHTML(htmlContent string) (string, error) {
	// Parse the body as HTML and look for the version field
	// It should look like this:
	// <dd>Version 1.21.0.1-25</dd>
	re := regexp.MustCompile(`<dd>\s*Version\s*([^\s<]+)\s*<\/dd>`)
	matches := re.FindStringSubmatch(htmlContent)
	// This will return an slice with two elements: The first is the full HTML tag (e.g. "<dd>Version...")
	// and the second is just the version number (the capture group in the regex)
	if len(matches) < 2 {
		return "", fmt.Errorf("version field not found")
	}
	// Return just the version number
	return matches[1], nil
}
