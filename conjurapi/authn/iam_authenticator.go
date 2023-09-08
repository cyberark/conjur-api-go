package authn

type IAMAuthenticator struct {
	Authenticate func() ([]byte, error)
}

func (a *IAMAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate()
}

func (a *IAMAuthenticator) NeedsTokenRefresh() bool {
	return false
}
