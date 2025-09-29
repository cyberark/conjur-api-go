package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// AzureAuthenticator handles authentication to Conjur using the authn-azure authenticator.
// It can either be provided a JWT token directly, or it can fetch a token from the Azure Instance Metadata Service (IMDS).
// It can optionally use a specific ClientID to request a token from IMDS.
type AzureAuthenticator struct {
	// The JWT token from Azure. If empty, a token will be fetched from IMDS.
	JWT string
	// Optional ClientID to use when fetching a token from IMDS.
	ClientID string
	// Authenticate is a function that takes an Azure JWT token and returns a Conjur access token or an error.
	// It will usually be set to Client.AzureAuthenticate.
	Authenticate func(azureToken string) ([]byte, error)
}

// RefreshToken fetches a new JWT token from IMDS if needed, then uses it to authenticate to Conjur and get a new access token.
func (a *AzureAuthenticator) RefreshToken() ([]byte, error) {
	err := a.RefreshJWT()
	if err != nil {
		return nil, err
	}
	return a.Authenticate(a.JWT)
}

// RefreshJWT fetches a new JWT token from IMDS if none is set.
func (a *AzureAuthenticator) RefreshJWT() error {
	// If a JWT is explicitly set, use it.
	if a.JWT != "" {
		logging.ApiLog.Debug("Using explicitly set Azure token")
		return nil
	}

	logging.ApiLog.Debug("No token set, fetching new token")
	token, err := a.AzureAuthenticateToken()
	if err != nil {
		return fmt.Errorf("Failed to refresh Azure token: %v", err)
	}
	a.JWT = token
	logging.ApiLog.Debug("Successfully fetched new token")

	return nil
}

func (a *AzureAuthenticator) NeedsTokenRefresh() bool {
	return false
}

type AzureResponse struct {
	AccessToken string `json:"access_token"`
}

// AzureAuthenticateToken fetches an Azure token from the Azure Instance Metadata Service (IMDS).
func (a *AzureAuthenticator) AzureAuthenticateToken() (string, error) {
	req, err := a.AzureTokenRequest()
	if err != nil {
		return "", err
	}

	// Call managed services for Azure resources token endpoint
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.ApiLog.Errorf("Error calling Azure token endpoint: %v", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Non-OK HTTP status: %s", resp.Status)
	}
	// Read response body
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.ApiLog.Errorf("Error reading the response body for Azure token: %v", err)
		return "", err
	}

	// Unmarshall response body into struct
	var r AzureResponse
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		logging.ApiLog.Errorf("Error unmarshalling the response for Azure token: %v", err)
		return "", err
	}

	return r.AccessToken, nil
}

// Create HTTP request for a managed services for Azure resources token to access Azure Resource Manager
func (a *AzureAuthenticator) AzureTokenRequest() (*http.Request, error) {
	azureBaseURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
	msi_endpoint, err := url.Parse(azureBaseURL)
	if err != nil {
		return nil, err
	}
	msi_parameters := msi_endpoint.Query()
	if a.ClientID != "" {
		msi_parameters.Add("client_id", a.ClientID)
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
