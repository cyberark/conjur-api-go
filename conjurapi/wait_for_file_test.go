package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
	"os"
	"io/ioutil"
)

func Test_waitForTextFile(t *testing.T) {
	Convey("Times out for non-existent filename", t, func() {
		bytes, err := waitForTextFile("path/to/non-existent/file", time.After(1 * time.Millisecond))
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Operation waitForTextFile timed out.")
		So(bytes, ShouldBeNil)
	})

	Convey("Returns bytes for eventually existent filename", t, func() {
		os.Remove("/tmp/random-file-to-exist")

		go func() {
			ioutil.WriteFile("/tmp/random-file-to-exist", []byte("some random stuff"), 0644)
		}()
		defer os.Remove("/tmp/random-file-to-exist")

		bytes, err := waitForTextFile("/tmp/random-file-to-exist", nil)

		So(err, ShouldBeNil)
		So(string(bytes), ShouldEqual, "some random stuff")

	})
}
