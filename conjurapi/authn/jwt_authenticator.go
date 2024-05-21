package authn

import (
	"fmt"
	"os"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

type JWTAuthenticator struct {
	JWT          string
	JWTFilePath  string
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
		jwtFilePath = k8sJWTPath
		logging.ApiLog.Debugf("No JWT file path set. Attempting to ready JWT from %s", jwtFilePath)
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
