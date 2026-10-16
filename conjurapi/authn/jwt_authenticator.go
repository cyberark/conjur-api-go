package authn

import (
	"context"
	"fmt"
	"os"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type JWTAuthenticator struct {
	JWT          string
	JWTFilePath  string
	// JWTProvider, when non-nil, is called on every RefreshJWT to obtain a
	// fresh JWT string from the SPIFFE Workload API. It takes precedence over
	// JWTFilePath and the Kubernetes service-account token path. Use
	// conjurapi/spiffe.NewJWTProvider() to source the token from a SPIRE agent.
	JWTProvider  func(context.Context) (string, error)
	// K8sTokenPath overrides the default Kubernetes service-account token path.
	// When empty, the well-known path is used. Intended for testing.
	K8sTokenPath string
	HostID       string
	Authenticate func(jwt, hostId string) ([]byte, error)
}

const k8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func (a *JWTAuthenticator) RefreshToken() ([]byte, error) {
	err := a.RefreshJWT()
	if err != nil {
		return nil, fmt.Errorf("Failed to refresh JWT: %v", err)
	}
	return a.Authenticate(a.JWT, a.HostID)
}

func (a *JWTAuthenticator) NeedsTokenRefresh() bool {
	return false
}

func (a *JWTAuthenticator) RefreshJWT() error {
	// SPIFFE Workload API path: call the provider on every refresh so the
	// provider's internal cache decides whether a new fetch is needed.
	if a.JWTProvider != nil {
		logging.ApiLog.Debugf("Fetching JWT from SPIFFE Workload API")
		token, err := a.JWTProvider(context.Background())
		if err != nil {
			return fmt.Errorf("SPIFFE JWT-SVID fetch failed: %w", err)
		}
		a.JWT = token
		return nil
	}

	// If a JWT token is already set or retrieved, do nothing.
	if a.JWT != "" {
		logging.ApiLog.Debugf("Using stored JWT")
		return nil
	}

	// If a token file path is provided, read the JWT token from the file.
	// Otherwise, read the token from the default Kubernetes service account path.
	var jwtFilePath string
	if a.JWTFilePath != "" {
		logging.ApiLog.Debugf("Reading JWT from %s", a.JWTFilePath)
		jwtFilePath = a.JWTFilePath
	} else {
		if a.K8sTokenPath != "" {
			jwtFilePath = a.K8sTokenPath
		} else {
			jwtFilePath = k8sJWTPath
		}
		logging.ApiLog.Debugf("No JWT file path set. Attempting to read JWT from %s", jwtFilePath)
	}

	token, err := readJWTFromFile(jwtFilePath)
	if err != nil {
		return err
	}
	a.JWT = token
	return nil
}

func readJWTFromFile(filePath string) (string, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
