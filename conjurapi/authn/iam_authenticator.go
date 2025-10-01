package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

// IAMAuthenticator handles authentication to Conjur using the authn-iam authenticator.
// It uses AWS SDK to sign a request to the AWS STS GetCallerIdentity endpoint and sends the signed headers to Conjur
// to get a Conjur access token.
type IAMAuthenticator struct {
	// Authenticate is a function that returns a Conjur access token or an error.
	// It will usually be set to Client.IAMAuthenticate.
	Authenticate func() ([]byte, error)
}

// RefreshToken uses the Authenticate function to get a new Conjur access token.
func (a *IAMAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate()
}

func (a *IAMAuthenticator) NeedsTokenRefresh() bool {
	return false
}

// IAMAuthenticateHeaders fetches AWS credentials and signs a request to the AWS STS GetCallerIdentity endpoint.
// These headers can then be sent to Conjur to authenticate using the authn-iam authenticator.
func IAMAuthenticateHeaders() ([]byte, error) {
	ctx := context.TODO()
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		logging.ApiLog.Errorf("Error loading AWS config: %v", err)
		return nil, err
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	request, err := buildRequest(cfg)
	if err != nil {
		return nil, err
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		logging.ApiLog.Errorf("Error loading AWS credentials: %v", err)
		return nil, err
	}

	// Sign the request
	signer := v4.NewSigner()
	// NOTE: The random-looking string is a hash of an empty payload which is necessary for the correct signature
	err = signer.SignHTTP(ctx, creds, request, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sts", cfg.Region, time.Now().UTC())
	if err != nil {
		logging.ApiLog.Errorf("Error signing HTTP request: %v", err)
		return nil, err
	}

	headerMap := make(map[string]interface{})
	for key, values := range request.Header {
		if len(values) == 1 {
			headerMap[key] = values[0]
		}
	}

	jsonData, err := json.Marshal(headerMap)
	if err != nil {
		logging.ApiLog.Errorf("Error marshalling signed headers to JSON: %v", err)
		return nil, err
	}

	return jsonData, nil
}

func buildRequest(cfg aws.Config) (*http.Request, error) {
	if !isValidAWSRegion(cfg.Region) {
		return nil, fmt.Errorf("Invalid AWS region: %s", cfg.Region)
	}

	var stsEndpoint string
	if cfg.Region == "global" {
		stsEndpoint = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
	} else {
		stsEndpoint = fmt.Sprintf("https://sts.%s.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", cfg.Region)
	}

	request, err := http.NewRequest(http.MethodGet, stsEndpoint, nil)
	if err != nil {
		logging.ApiLog.Errorf("Error creating HTTP request: %v", err)
		return nil, err
	}

	if !isValidAWSHost(request.Host) {
		return nil, fmt.Errorf("Invalid AWS STS endpoint host: %s", request.Host)
	}

	request.Header.Set("Host", request.Host)
	return request, nil
}

func isValidAWSRegion(region string) bool {
	// Basic validation for AWS region format. An invalid region could lead to vulnerabilities.
	if region == "global" {
		return true
	}

	return regexp.MustCompile(`^([a-z]{2}(-gov)?-[a-z]+-\d)$`).MatchString(region)
}

func isValidAWSHost(host string) bool {
	// Extra validation to ensure the STS host is not manipulated to point to a non-AWS domain
	return strings.HasSuffix(host, ".amazonaws.com")
}
