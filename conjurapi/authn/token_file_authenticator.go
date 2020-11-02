package authn

import (
	"os"
	"time"
)

type TokenFileAuthenticator struct {
	MaxWaitTime time.Duration
	TokenFile   string `env:"CONJUR_AUTHN_TOKEN_FILE"`

	mTime    time.Time
	username string
}

func (a *TokenFileAuthenticator) RefreshToken() ([]byte, error) {
	maxWaitTime := a.MaxWaitTime
	var timeout <-chan time.Time
	if maxWaitTime == -1 {
		timeout = nil
	} else {
		timeout = time.After(a.MaxWaitTime)
	}

	bytes, err := waitForTextFile(a.TokenFile, timeout)
	if err != nil {
		return nil, err
	}

	fi, _ := os.Stat(a.TokenFile)
	a.mTime = fi.ModTime()

	token, err := NewToken(bytes)
	if err != nil {
		return nil, err
	}
	a.username = token.Username()

	return bytes, err
}

func (a *TokenFileAuthenticator) NeedsTokenRefresh() bool {
	fi, err := os.Stat(a.TokenFile)
	if err != nil && os.IsNotExist(err) {
		return true
	}

	return a.mTime != fi.ModTime()
}

func (a *TokenFileAuthenticator) Username() (string, error) {
	if a.NeedsTokenRefresh() {
		_, err := a.RefreshToken()
		if err != nil {
			return "", err
		}
	}

	return a.username, nil
}
