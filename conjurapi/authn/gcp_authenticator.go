package authn

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

const GcpMetadataFlavorHeaderName = "Metadata-Flavor"
const GcpMetadataFlavorHeaderValue = "Google"
const GcpIdentityURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"

// GCPAuthenticator handles authentication to Conjur using the authn-gcp authenticator.
// It can either be provided a JWT token directly, or it can fetch a token from the GCP Metadata service.
// It requires the Conjur account name and host ID. It can optionally override the default GCP identity URL.
type GCPAuthenticator struct {
	// The Conjur account name.
	Account string
	// The JWT token from GCP. If empty, a token will be fetched from the GCP Metadata service.
	JWT string
	// The HostID to use for authentication to Conjur.
	HostID string
	// The GCP Metadata service URL to fetch the identity token from. Defaults to the standard GCP metadata URL.
	GCPIdentityUrl string
	// Authenticate is a function that takes a GCP JWT token and returns a Conjur access token or an error.
	// It will usually be set to Client.GCPAuthenticate.
	Authenticate func(gcpToken string) ([]byte, error)
}

// RefreshToken fetches a new JWT token from the GCP Metadata service if needed, then uses it to authenticate to Conjur and get a new access token.
func (a *GCPAuthenticator) RefreshToken() ([]byte, error) {
	err := a.RefreshJWT()
	if err != nil {
		return nil, err
	}
	return a.Authenticate(a.JWT)
}

func (a *GCPAuthenticator) NeedsTokenRefresh() bool {
	return false
}

// RefreshJWT fetches a new JWT token from the GCP Metadata service if none is set.
func (a *GCPAuthenticator) RefreshJWT() error {
	// If a JWT is explicitly set, use it.
	if a.JWT != "" {
		logging.ApiLog.Debug("Using explicitly set GCP token")
		return nil
	}

	logging.ApiLog.Debug("No token set, fetching new token")
	token, err := a.GCPAuthenticateToken()
	if err != nil {
		return fmt.Errorf("Failed to refresh GCP token: %v", err)
	}
	a.JWT = token
	logging.ApiLog.Debug("Successfully fetched new token")

	return nil
}

// GCPAuthenticateToken fetches a GCP token from the GCP Metadata service.
func (a *GCPAuthenticator) GCPAuthenticateToken() (string, error) {
	// Build query parameters
	params := url.Values{}
	audience := "conjur/" + a.Account + "/host/" + a.HostID
	params.Add("audience", audience)
	params.Add("format", "full")

	// Build final URL with encoded parameters
	fullURL := fmt.Sprintf("%s?%s", a.GCPIdentityUrl, params.Encode())
	// Create a new request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		logging.ApiLog.Fatalf("Failed to create request for GCP metadata token: %v", err)
		return "", err
	}

	// Set required header
	req.Header.Add(GcpMetadataFlavorHeaderName, GcpMetadataFlavorHeaderValue)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logging.ApiLog.Fatalf("Request failed for GCP Metadata token: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Check if response status is not 200 (OK)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response: %v", resp.Status)
	}

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.ApiLog.Fatalf("Failed to read response for GCP metadata token: %v", err)
		return "", err
	}

	return string(body), nil
}
