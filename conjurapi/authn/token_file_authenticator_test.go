package authn

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ensureWriteFile(filepath, filecontents string) {
	var prevModTime time.Time

	info, err := os.Stat(filepath)
	// Panic for any error that is not! NotExist
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	// Register the previous ModTime, otherwise there is no previous file so fall back to a second before this is
	if err != nil {
		prevModTime = info.ModTime()
	} else {
		prevModTime = time.Now().Add(-time.Second)
	}

	err = os.WriteFile(filepath, []byte(filecontents), 0600)
	if err != nil {
		panic(err)
	}

	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		select {
		// Timeout after 10 seconds. Clearly there's something wrong with i/o
		case <-timeout:
			err := fmt.Errorf("ensureWriteFile timed out.")

			panic(err)
		// Return only if the current ModTime is greater than the previous ModTime
		case <-ticker.C:
			info, err := os.Stat(filepath)
			if err != nil || !info.ModTime().After(prevModTime) {
				continue
			}

			return
		}
	}
}

func TestTokenFileAuthenticator_RefreshToken(t *testing.T) {
	t.Run("Retrieve existent token file", func(t *testing.T) {
		token_file, _ := os.CreateTemp("", "existent-token-file")
		token_file_name := token_file.Name()
		defer os.Remove(token_file_name)

		token_file_contents := "token-from-file-contents"
		ensureWriteFile(token_file_name, token_file_contents)

		authenticator := TokenFileAuthenticator{
			MaxWaitTime: 1 * time.Second,
			TokenFile:   token_file_name,
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, "token-from-file-contents", string(token))
	})

	t.Run("Retrieve eventually existent token file", func(t *testing.T) {
		token_dir := t.TempDir()
		token_file_name := path.Join(token_dir, "token")

		token_file_contents := "token-from-file-contents"
		go func() {
			os.WriteFile(token_file_name, []byte(token_file_contents), 0600)
		}()

		authenticator := TokenFileAuthenticator{
			TokenFile:   token_file_name,
			MaxWaitTime: 10 * time.Second, // The write takes place in a go routine so we need to account for slow i/o
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, "token-from-file-contents", string(token))
	})

	t.Run("Times out on never-existent token file", func(t *testing.T) {
		token_file := "/path/to/non-existent-token-file"

		authenticator := TokenFileAuthenticator{
			TokenFile:   token_file,
			MaxWaitTime: 10 * time.Millisecond, // Something non-zero, since zero means immediate failure
		}

		token, err := authenticator.RefreshToken()

		assert.Nil(t, token)
		assert.Error(t, err)
		assert.Equal(t, "Operation waitForTextFile timed out.", err.Error())
	})

	t.Run("Doesn't time out if MaxWaitTime is -1", func(t *testing.T) {
		tempDir := t.TempDir()
		token_file_name := path.Join(tempDir, "token")

		go func() {
			// Wait some time before writing the file
			time.Sleep(500 * time.Millisecond)
			token_file_contents := "token-from-file-contents"
			os.WriteFile(token_file_name, []byte(token_file_contents), 0600)
		}()

		authenticator := TokenFileAuthenticator{
			TokenFile:   token_file_name,
			MaxWaitTime: -1, // Disable timeout
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, "token-from-file-contents", string(token))
	})
}

func TestTokenFileAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Token refresh needed after updates", func(t *testing.T) {
		token_file, _ := os.CreateTemp("", "existent-token-file")
		token_file_name := token_file.Name()
		defer os.Remove(token_file_name)

		ensureWriteFile(token_file_name, "token-from-file-contents")

		authenticator := TokenFileAuthenticator{
			TokenFile:   token_file_name,
			MaxWaitTime: 1 * time.Second,
		}

		// Read
		_, err := authenticator.RefreshToken()
		assert.NoError(t, err)

		// Return false for unmodified file
		assert.False(t, authenticator.NeedsTokenRefresh())

		ensureWriteFile(token_file_name, "recent modification")

		// Return true for modified file
		assert.True(t, authenticator.NeedsTokenRefresh())
	})
}
