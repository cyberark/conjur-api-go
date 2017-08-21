package conjurapi

import (
	"testing"
	"os"
	"io/ioutil"
	. "github.com/smartystreets/goconvey/convey"
	"fmt"
	"math/rand"
)

func TestTokenFileAuthenticator_RefreshToken(t *testing.T) {
	Convey("Given existent token filename", t, func() {
		token_file :=	"/tmp/existent-token-file"
		token_file_contents := "token-from-file-contents"
		os.Remove("/tmp/existent-token-file")
		go func() {
			ioutil.WriteFile(token_file, []byte(token_file_contents), 0644)
		}()
		defer os.Remove(token_file)

		Convey("Return the token from the file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}

			token, err := authenticator.RefreshToken()

			So(err, ShouldBeNil)
			So(string(token), ShouldEqual, "token-from-file-contents")
		})
	})

	Convey("Given a non-existent token filename", t, func() {
		token_file :=	"/tmp/non-existent-token-file"

		Convey("Return nil with error", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}

			token, err := authenticator.RefreshToken()

			So(token, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Operation waitForTextFile timed out.")
		})
	})
}

func TestTokenFileAuthenticator_NeedsTokenRefresh(t *testing.T) {
	Convey("Given existent token filename", t, func() {
		token_file := fmt.Sprintf("/tmp/existent-token-file-%v", rand.Intn(100))
		token_file_contents := "token-from-file-contents"
		os.Remove(token_file)
		go func() {
			ioutil.WriteFile(token_file, []byte(token_file_contents), 0644)
		}()
		defer os.Remove(token_file)

		Convey("Return true for recently modified file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}
			authenticator.RefreshToken()

			ioutil.WriteFile(token_file, []byte("some random stuff"), 0644)

			So(authenticator.NeedsTokenRefresh(), ShouldBeTrue)
		})

		Convey("Return false for unmodified file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}
			authenticator.RefreshToken()

			So(authenticator.NeedsTokenRefresh(), ShouldBeFalse)
		})
	})
}