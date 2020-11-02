package authn

import (
	"io/ioutil"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestTokenAuthenticator_NeedsTokenRefresh(t *testing.T) {
	Convey("Returns false", t, func() {
		authenticator := TokenAuthenticator{}

		So(authenticator.NeedsTokenRefresh(), ShouldBeFalse)
	})
}

func TestTokenAuthenticator_Username(t *testing.T) {
	token_v5, err := ioutil.ReadFile("testdata/token_v5.json")
	if err != nil {
		t.Fatalf("Unable to read test token_v5!")
		return
	}

	token_v4, err := ioutil.ReadFile("testdata/token_v4.json")
	if err != nil {
		t.Fatalf("Unable to read test token_v4!")
		return
	}

	Convey("Raises error if token is invalid", t, func() {
		authenticator := TokenAuthenticator{
			Token: "badtoken",
		}

		_, err := authenticator.Username()

		So(err, ShouldNotBeNil)
		So(
			err.Error(),
			ShouldEqual,
			"Unable to unmarshal token : invalid character 'b' looking for beginning of value",
		)
	})

	Convey("Works when token file is a v4 token", t, func() {
		authenticator := TokenAuthenticator{
			Token: string(token_v4),
		}

		username, err := authenticator.Username()

		So(err, ShouldBeNil)
		So(username, ShouldEqual, "admin")
	})

	Convey("Works when token file is a v5 token", t, func() {
		authenticator := TokenAuthenticator{
			Token: string(token_v5),
		}

		username, err := authenticator.Username()

		So(err, ShouldBeNil)
		So(username, ShouldEqual, "admin")
	})
}
