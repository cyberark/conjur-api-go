package authn

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestAPIKeyAuthenticator_RefreshToken(t *testing.T) {
	Convey("Given valid credentials", t, func() {
		Login := "valid-login"
		APIKey := "valid-api-key"
		Authenticate := func(loginPair LoginPair) ([]byte, error) {
			if loginPair.Login == "valid-login" && loginPair.APIKey == "valid-api-key" {
				return []byte("data"), nil
			} else {
				return nil, fmt.Errorf("401 Invalid")
			}
		}

		Convey("Returns the token bytes", func() {
			authenticator := APIKeyAuthenticator{
				Authenticate: Authenticate,
				LoginPair: LoginPair{
					Login:  Login,
					APIKey: APIKey,
				},
			}

			token, err := authenticator.RefreshToken()

			So(err, ShouldBeNil)
			So(string(token), ShouldContainSubstring, "data")
		})

		Convey("Given invalid credentials", func() {
			Login = "invalid-login"

			Convey("Return nil with error", func() {
				authenticator := APIKeyAuthenticator{
					Authenticate: Authenticate,
					LoginPair: LoginPair{
						Login:  Login,
						APIKey: APIKey,
					},
				}

				token, err := authenticator.RefreshToken()

				So(token, ShouldBeNil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "401")
			})
		})
	})
}

func TestAPIKeyAuthenticator_NeedsTokenRefresh(t *testing.T) {
	Convey("Returns false", t, func() {
		authenticator := APIKeyAuthenticator{}

		So(authenticator.NeedsTokenRefresh(), ShouldBeFalse)
	})
}

func TestAPIKeyAuthenticator_Username(t *testing.T) {
	Convey("Given valid credentials", t, func() {
		Login := "valid-login"
		APIKey := "valid-api-key"
		Authenticate := func(loginPair LoginPair) ([]byte, error) {
			if loginPair.Login == "valid-login" && loginPair.APIKey == "valid-api-key" {
				return []byte("data"), nil
			} else {
				return nil, fmt.Errorf("401 Invalid")
			}
		}

		Convey("Uses the username from the LoginPair", func() {
			authenticator := APIKeyAuthenticator{
				Authenticate: Authenticate,
				LoginPair: LoginPair{
					Login:  Login,
					APIKey: APIKey,
				},
			}

			username, err := authenticator.Username()

			So(err, ShouldBeNil)
			So(username, ShouldEqual, "valid-login")
		})
	})
}
