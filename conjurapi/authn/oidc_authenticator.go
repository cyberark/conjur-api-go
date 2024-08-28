package authn

type OidcAuthenticator struct {
	Code         string
	Nonce        string
	CodeVerifier string
	Authenticate func(code, nonce, code_verifier string) ([]byte, error)
}

func (a *OidcAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate(a.Code, a.Nonce, a.CodeVerifier)
}

func (a *OidcAuthenticator) NeedsTokenRefresh() bool {
	return false
}

type OidcTokenAuthenticator struct {
	Token        string
	Authenticate func(token string) ([]byte, error)
}

func (a *OidcTokenAuthenticator) RefreshToken() ([]byte, error) {
	return a.Authenticate(a.Token)
}

func (a *OidcTokenAuthenticator) NeedsTokenRefresh() bool {
	return false
}
