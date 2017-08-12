package conjurapi

import (
	"time"
	"fmt"
	"os"
	"io/ioutil"
)

func waitForTextFile(fileName string, timeout <-chan time.Time) (string, error) {
	for  {
		select {
		case <-timeout:
			return "", fmt.Errorf("Operation WaitForTextFile timed out.")
		default:
			if _, err := os.Stat(fileName); os.IsNotExist(err) {
				time.Sleep(1 * time.Second)
			} else {
				b, err := ioutil.ReadFile(fileName)
				return string(b), err
			}
		}
	}
}