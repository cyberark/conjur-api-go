package authn

import (
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestTokenFileAuthenticator_RefreshToken(t *testing.T) {
	token_v5, err := ioutil.ReadFile("testdata/token_v5.json")
	if err != nil {
		t.Fatalf("Unable to read test token!")
		return
	}

	Convey("Given existent token filename", t, func() {

		Convey("Return the token from the file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: "testdata/token_v5.json",
			}

			token, err := authenticator.RefreshToken()

			So(err, ShouldBeNil)
			So(string(token), ShouldEqual, string(token_v5))
		})
	})

	Convey("Given an eventually existent token filename", t, func() {
		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()

		Convey("Return the token from the file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile:   token_file_name,
				MaxWaitTime: 5000 * time.Millisecond,
			}

			os.Remove(token_file_name)
			defer os.Remove(token_file_name)
			go func() {
				time.Sleep(100 * time.Millisecond)
				ioutil.WriteFile(token_file_name, []byte(token_v5), 0600)
			}()

			actual_token, err := authenticator.RefreshToken()

			So(err, ShouldBeNil)
			So(string(actual_token), ShouldEqual, string(token_v5))
		})
	})

	Convey("Given a non-existent token filename", t, func() {
		token_file := "/path/to/non-existent-token-file"

		Convey("Return nil token with error", func() {
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
		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()
		token_file_contents := "token-from-file-contents"
		token_file.Write([]byte(token_file_contents))
		defer os.Remove(token_file_name)

		Convey("Return true for recently modified file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file_name,
			}
			authenticator.RefreshToken()

			time.Sleep(1000 * time.Millisecond)
			token_file.Write([]byte("recent modification"))

			So(authenticator.NeedsTokenRefresh(), ShouldBeTrue)
		})

		Convey("Return false for unmodified file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file_name,
			}
			authenticator.RefreshToken()

			So(authenticator.NeedsTokenRefresh(), ShouldBeFalse)
		})
	})
}

func TestTokenFileAuthenticator_Username(t *testing.T) {
	Convey("Given existent token filename", t, func() {
		Convey("Raises error if token is invalid", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: "testdata/bad_token.json",
			}

			_, err := authenticator.Username()

			So(err, ShouldNotBeNil)
			So(
				err.Error(),
				ShouldEqual,
				"Unable to unmarshal token : invalid character 'o' in literal true (expecting 'r')",
			)
		})

		Convey("Works when token file is a v4 token", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: "testdata/token_v4.json",
			}

			username, err := authenticator.Username()

			So(err, ShouldBeNil)
			So(username, ShouldEqual, "admin")
		})

		Convey("Works when token file is a v5 token", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: "testdata/token_v5.json",
			}

			username, err := authenticator.Username()

			So(err, ShouldBeNil)
			So(username, ShouldEqual, "admin")
		})
	})

	Convey("Given an eventually existent token filename", t, func() {
		token_v5, err := ioutil.ReadFile("testdata/token_v5.json")
		So(err, ShouldBeNil)
		if err != nil {
			return
		}

		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()

		Convey("Return the username from the file", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile:   token_file_name,
				MaxWaitTime: 5000 * time.Millisecond,
			}

			os.Remove(token_file_name)
			defer os.Remove(token_file_name)
			go func() {
				time.Sleep(100 * time.Millisecond)
				ioutil.WriteFile(token_file_name, []byte(token_v5), 0600)
			}()

			username, err := authenticator.Username()

			So(err, ShouldBeNil)
			So(username, ShouldEqual, "admin")
		})
	})

	Convey("Given a non-existent token filename", t, func() {
		token_file := "/path/to/non-existent-token-file"

		Convey("Return empty username with error", func() {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}

			username, err := authenticator.Username()

			So(username, ShouldBeEmpty)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Operation waitForTextFile timed out.")
		})
	})
}
