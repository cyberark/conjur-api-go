package authn

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
	"github.com/spf13/afero"
)

func Test_waitForTextFile(t *testing.T) {
	AppFS = afero.NewMemMapFs()

	Convey("Times out for non-existent filename", t, func() {
		bytes, err := waitForTextFile("path/to/non-existent/file", time.After(0))
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "Operation waitForTextFile timed out.")
		So(bytes, ShouldBeNil)
	})

	Convey("Returns bytes for eventually existent filename", t, func() {
		file_to_exist, _ := afero.TempFile(AppFS, "", "existent-file")
		file_to_exist_name := file_to_exist.Name()

		AppFS.Remove(file_to_exist_name)
		go func() {
			afero.WriteFile(AppFS, file_to_exist_name, []byte("some random stuff"), 0600)
		}()
		defer AppFS.Remove(file_to_exist_name)

		bytes, err := waitForTextFile(file_to_exist_name, nil)

		So(err, ShouldBeNil)
		So(string(bytes), ShouldEqual, "some random stuff")

	})
}
