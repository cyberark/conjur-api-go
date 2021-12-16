package authn

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenFileAuthenticator_RefreshToken(t *testing.T) {
	t.Run("Given existent token filename", func(t *testing.T) {
		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()
		token_file_contents := "token-from-file-contents"
		token_file.Write([]byte(token_file_contents))
		token_file.Close()
		defer os.Remove(token_file_name)

		t.Run("Return the token from the file", func(t *testing.T) {
			authenticator := TokenFileAuthenticator{
				TokenFile:   token_file_name,
				MaxWaitTime: 500 * time.Millisecond,
			}

			token, err := authenticator.RefreshToken()

			assert.NoError(t, err)
			assert.Equal(t, "token-from-file-contents", string(token))
		})
	})

	t.Run("Given an eventually existent token filename", func(t *testing.T) {
		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()

		token_file_contents := "token-from-file-contents"
		os.Remove(token_file_name)
		go func() {
			ioutil.WriteFile(token_file_name, []byte(token_file_contents), 0600)
		}()
		defer os.Remove(token_file_name)

		t.Run("Return the token from the file", func(t *testing.T) {
			authenticator := TokenFileAuthenticator{
				TokenFile:   token_file_name,
				MaxWaitTime: 500 * time.Millisecond,
			}

			token, err := authenticator.RefreshToken()

			assert.NoError(t, err)
			assert.Equal(t, "token-from-file-contents", string(token))
		})
	})

	t.Run("Given a non-existent token filename", func(t *testing.T) {
		token_file := "/path/to/non-existent-token-file"

		t.Run("Return nil with error", func(t *testing.T) {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file,
			}

			token, err := authenticator.RefreshToken()

			assert.Nil(t, token)
			assert.Error(t, err)
			assert.Equal(t, "Operation waitForTextFile timed out.", err.Error())
		})
	})
}

func TestTokenFileAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Given existent token filename", func(t *testing.T) {
		token_file, _ := ioutil.TempFile("", "existent-token-file")
		token_file_name := token_file.Name()
		token_file_contents := "token-from-file-contents"
		token_file.Write([]byte(token_file_contents))
		// Ensure the file is written to the disk
		token_file.Sync()
		defer os.Remove(token_file_name)

		t.Run("Return true for recently modified file", func(t *testing.T) {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file_name,
			}
			_, err := authenticator.RefreshToken()
			assert.NoError(t, err)

			time.Sleep(time.Second)
			token_file.Write([]byte("recent modification"))
			// Ensure the modification is written to the disk
			token_file.Sync()

			time.Sleep(time.Second)
			assert.True(t, authenticator.NeedsTokenRefresh())
		})

		t.Run("Return false for unmodified file", func(t *testing.T) {
			authenticator := TokenFileAuthenticator{
				TokenFile: token_file_name,
			}
			_, err := authenticator.RefreshToken()
			assert.NoError(t, err)

			assert.False(t, authenticator.NeedsTokenRefresh())
		})
	})
}
