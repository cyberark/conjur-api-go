package authn

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

const MetadataFlavorHeaderName = "Metadata-Flavor"
const MetadataFlavorHeaderValue = "Google"

type GCPAuthenticator struct {
	Authenticate func() ([]byte, error)
}

func (a *GCPAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate()
}

func (a *GCPAuthenticator) NeedsTokenRefresh() bool {
	return false
}

func GCPAuthenticateToken(account, hostID string, baseUrl string) ([]byte, error) {
	// Build query parameters
	params := url.Values{}
	audience := "conjur/" + account + "/host/" + hostID
	params.Add("audience", audience)
	params.Add("format", "full")

	// Build final URL with encoded parameters
	fullURL := fmt.Sprintf("%s?%s", baseUrl, params.Encode())
	// Create a new request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request for GCP metadata token: %v", err)
		return nil, err
	}

	// Set required header
	req.Header.Add(MetadataFlavorHeaderName, MetadataFlavorHeaderValue)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed for GCP Metadata token: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Check if response status is not 200 (OK)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %v", resp.Status)
	}

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response for GCP metadata token: %v", err)
		return nil, err
	}

	return body, nil
}
