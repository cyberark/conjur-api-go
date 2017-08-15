package conjurapi

import (
	"testing"
	"os"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAPIKeyAuthenticator_RefreshToken(t *testing.T) {
	Convey("Given valid credentials", t, func() {
		AuthnURLTemplate := AuthnURL(os.Getenv("CONJUR_APPLIANCE_URL"), os.Getenv("CONJUR_ACCOUNT"))
		Login := os.Getenv("CONJUR_AUTHN_LOGIN")
		APIKey := os.Getenv("CONJUR_AUTHN_API_KEY")


		Convey("Return the token bytes", func() {
			authenticator := APIKeyAuthenticator{
				AuthnURLTemplate: AuthnURLTemplate,
				Login: Login,
				APIKey: APIKey,
			}

			token, err := authenticator.RefreshToken()

			So(err, ShouldBeNil)
			So(string(token), ShouldContainSubstring, "data")
		})

		Convey("Given invalid credentials", func() {
			Login = "invalid-login"

			Convey("Return nil with error", func() {
				authenticator := APIKeyAuthenticator{
					AuthnURLTemplate: AuthnURLTemplate,
					Login: Login,
					APIKey: APIKey,
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