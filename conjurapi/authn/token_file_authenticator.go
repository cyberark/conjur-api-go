package authn

import (
	"os"
	"time"
)

// statFile is a seam so tests can simulate the token file vanishing between
// the read and the stat.
var statFile = os.Stat

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
	if err != nil {
		return bytes, err
	}

	fi, err := statFile(a.TokenFile)
	if err != nil {
		// The file vanished (or became unreadable) between the read and the
		// stat. Without a modification time we cannot track changes, so report
		// the error rather than return a token we can't track. a.mTime is left
		// unchanged, so NeedsTokenRefresh keeps returning true.
		return nil, err
	}
	a.mTime = fi.ModTime()
	return bytes, nil
}

// NeedsTokenRefresh checks if the token file has been modified since the last read.
func (a *TokenFileAuthenticator) NeedsTokenRefresh() bool {
	fi, err := statFile(a.TokenFile)
	if err != nil {
		// File is missing or unreadable: request a refresh so RefreshToken
		// waits for / reports on the file instead of dereferencing a nil FileInfo.
		return true
	}
	return a.mTime != fi.ModTime()
}
