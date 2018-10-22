package authn

import (
	"fmt"
	"os"
	"time"
	"github.com/spf13/afero"
)

func waitForTextFile(fileName string, timeout <-chan time.Time) ([]byte, error) {
	var (
		fileBytes []byte
		err       error
	)

waiting_loop:
	for {
		select {
		case <-timeout:
			err = fmt.Errorf("Operation waitForTextFile timed out.")
			break waiting_loop
		default:
			if _, err := AppFS.Stat(fileName); os.IsNotExist(err) {
				time.Sleep(100 * time.Millisecond)
			} else {
				fileBytes, err = afero.ReadFile(AppFS, fileName)
				break waiting_loop
			}
		}
	}

	return fileBytes, err
}
