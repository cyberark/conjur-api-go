package authn

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_waitForTextFile(t *testing.T) {
	t.Run("Times out for non-existent filename", func(t *testing.T) {
		bytes, err := waitForTextFile("path/to/non-existent/file", time.After(0))
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "Operation waitForTextFile timed out.")
		assert.Nil(t, bytes)
	})

	t.Run("Returns bytes for eventually existent filename", func(t *testing.T) {
		file_to_exist, _ := ioutil.TempFile("", "existent-file")
		file_to_exist_name := file_to_exist.Name()

		os.Remove(file_to_exist_name)
		go func() {
			ioutil.WriteFile(file_to_exist_name, []byte("some random stuff"), 0600)
		}()
		defer os.Remove(file_to_exist_name)

		bytes, err := waitForTextFile(file_to_exist_name, nil)

		assert.NoError(t, err)
		assert.Equal(t, "some random stuff", string(bytes))

	})
}
