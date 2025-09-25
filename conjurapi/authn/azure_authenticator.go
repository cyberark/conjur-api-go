package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type AzureAuthenticator struct {
	Authenticate func() ([]byte, error)
}

func (a *AzureAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate()
}

func (a *AzureAuthenticator) NeedsTokenRefresh() bool {
	return false
}

type AzureResponse struct {
	AccessToken string `json:"access_token"`
}

func AzureAuthenticateToken(clientID string) ([]byte, error) {
	req, err := AzureTokenRequest(clientID)
	if err != nil {
		return nil, err
	}

	// Call managed services for Azure resources token endpoint
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.ApiLog.Errorf("Error calling Azure token endpoint: %v", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Non-OK HTTP status: %s", resp.Status)
	}
	// Read response body
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.ApiLog.Errorf("Error reading the response body for Azure token: %v", err)
		return nil, err
	}

	// Unmarshall response body into struct
	var r AzureResponse
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		logging.ApiLog.Errorf("Error unmarshalling the response for Azure token: %v", err)
		return nil, err
	}

	return []byte(r.AccessToken), nil
}

// Create HTTP request for a managed services for Azure resources token to access Azure Resource Manager
func AzureTokenRequest(clientID string) (*http.Request, error) {
	azureBaseURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
	msi_endpoint, err := url.Parse(azureBaseURL)
	if err != nil {
		return nil, err
	}
	msi_parameters := msi_endpoint.Query()
	if clientID != "" {
		msi_parameters.Add("client_id", clientID)
	}
	msi_parameters.Add("resource", "https://management.azure.com/")
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		logging.ApiLog.Errorf("Error creating HTTP request: %v", err)
		return nil, err
	}
	req.Header.Add("Metadata", "true")

	return req, nil
}
