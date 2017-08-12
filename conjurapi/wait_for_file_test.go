package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
	"os"
	"io/ioutil"
)

func Test_waitForTextFile(t *testing.T) {
	Convey("Non existent file times out", t, func() {
		text, err := waitForTextFile("path/to/non-existent/file", time.After(1 * time.Millisecond))
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Operation WaitForTextFile timed out.")
		So(text, ShouldBeBlank)
	})

	Convey("Eventually existent file is read", t, func() {
		os.Remove("/tmp/random-file-to-exist")

		go func() {
			ioutil.WriteFile("/tmp/random-file-to-exist", []byte("some random stuff"), 0644)
		}()
		defer os.Remove("/tmp/random-file-to-exist")

		text, err := waitForTextFile("/tmp/random-file-to-exist", nil)

		So(err, ShouldBeNil)
		So(text, ShouldEqual, "some random stuff")

	})
}
