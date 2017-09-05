package authn

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
	"os"
	"io/ioutil"
)

func Test_waitForTextFile(t *testing.T) {
	Convey("Times out for non-existent filename", t, func() {
		bytes, err := waitForTextFile("path/to/non-existent/file", time.After(0))
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Operation waitForTextFile timed out.")
		So(bytes, ShouldBeNil)
	})

	Convey("Returns bytes for eventually existent filename", t, func() {
		file_to_exist, _ := ioutil.TempFile("", "existent-file")
		file_to_exist_name := file_to_exist.Name()

		os.Remove(file_to_exist_name)
		go func() {
			ioutil.WriteFile(file_to_exist_name, []byte("some random stuff"), 0600)
		}()
		defer os.Remove(file_to_exist_name)

		bytes, err := waitForTextFile(file_to_exist_name, nil)

		So(err, ShouldBeNil)
		So(string(bytes), ShouldEqual, "some random stuff")

	})
}
