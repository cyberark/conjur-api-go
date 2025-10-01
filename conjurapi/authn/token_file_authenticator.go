package authn

import (
	"os"
	"time"
)

// TokenFileAuthenticator handles authentication to Conjur where a Conjur access token is read from a file.
type TokenFileAuthenticator struct {
	TokenFile   string `env:"CONJUR_AUTHN_TOKEN_FILE"`
	mTime       time.Time
	MaxWaitTime time.Duration
}

// RefreshToken reads and returns the Conjur access token from the specified file.
func (a *TokenFileAuthenticator) RefreshToken() ([]byte, error) {
	// TODO: is this implementation concurrent ?
	maxWaitTime := a.MaxWaitTime
	var timeout <-chan time.Time
	if maxWaitTime == -1 {
		timeout = nil
	} else {
		timeout = time.After(a.MaxWaitTime)
	}

	bytes, err := waitForTextFile(a.TokenFile, timeout)
	if err == nil {
		fi, _ := os.Stat(a.TokenFile)
		a.mTime = fi.ModTime()
	}
	return bytes, err
}

// NeedsTokenRefresh checks if the token file has been modified since the last read.
func (a *TokenFileAuthenticator) NeedsTokenRefresh() bool {
	fi, _ := os.Stat(a.TokenFile)
	return a.mTime != fi.ModTime()
}
