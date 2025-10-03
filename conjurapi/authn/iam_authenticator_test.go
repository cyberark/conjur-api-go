package authn

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRequest(t *testing.T) {
	testCases := []struct {
		name        string
		config      aws.Config
		expectError string
		expectHost  string
	}{
		{
			name: "Valid region",
			config: aws.Config{
				Region: "us-west-2",
			},
			expectError: "",
			expectHost:  "sts.us-west-2.amazonaws.com",
		},
		{
			name: "Global region",
			config: aws.Config{
				Region: "global",
			},
			expectError: "",
			expectHost:  "sts.amazonaws.com",
		},
		{
			name: "Empty region",
			config: aws.Config{
				Region: "",
			},
			expectError: "Invalid AWS region",
		},
		{
			name: "Invalid region",
			config: aws.Config{
				Region: "invalid?region",
			},
			expectError: "Invalid AWS region",
			expectHost:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildRequest(tc.config)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, req)

				assert.Equal(t, tc.expectHost, req.Host)
			}
		})
	}
}

func TestIsValidAWSRegion(t *testing.T) {
	testCases := []struct {
		region      string
		expectValid bool
	}{
		{"us-east-1", true},
		{"us-west-2", true},
		{"us-gov-west-1", true},
		{"global", true},
		{"invalid-region", false},
		{"us_east_1", false},
		{"us-east-1!", false},
		{"foo?bar", false},
	}

	for _, tc := range testCases {
		t.Run(tc.region, func(t *testing.T) {
			isValid := isValidAWSRegion(tc.region)
			assert.Equal(t, tc.expectValid, isValid)
		})
	}
}

func TestIsValidAWSHost(t *testing.T) {
	testCases := []struct {
		host        string
		expectValid bool
	}{
		{"sts.us-east-1.amazonaws.com", true},
		{"sts.us-gov-west-1.amazonaws.com", true},
		{"sts.us-east-1.amazonaws.com.malware.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			isValid := isValidAWSHost(tc.host)
			assert.Equal(t, tc.expectValid, isValid)
		})
	}
}
