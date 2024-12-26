package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateMinVersion(t *testing.T) {
	tests := []struct {
		actualVersion string
		minVersion    string
		expectedError string
	}{
		{"1.0.0", "1.0.0", ""},
		{"1.0.1", "1.0.0", ""},
		{"1.1.0", "1.0.0", ""},
		{"2.0.0", "1.0.0", ""},
		{"1.0.0", "1.0.1", "Conjur version 1.0.0 is less than the minimum required version 1.0.1"},
		{"1.0.0", "2.0.0", "Conjur version 1.0.0 is less than the minimum required version 2.0.0"},
		{"invalid", "1.0.0", "failed to parse server version: Invalid Semantic Version"},
		{"1.0.0", "invalid", "failed to parse minimum version: Invalid Semantic Version"},
	}

	for _, test := range tests {
		err := validateMinVersion(test.actualVersion, test.minVersion)
		if test.expectedError == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, test.expectedError)
		}
	}
}
