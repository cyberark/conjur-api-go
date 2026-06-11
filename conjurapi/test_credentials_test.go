package conjurapi

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	testCredentials     map[string]string
	testCredentialsOnce sync.Once
)

func loadTestCredentials() {
	testCredentialsOnce.Do(func() {
		testCredentials = make(map[string]string)
		_, file, _, _ := runtime.Caller(0)
		path := filepath.Join(filepath.Dir(file), "testdata", "credentials.env")
		f, err := os.Open(path)
		if err != nil {
			panic("load test credentials: " + err.Error())
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			testCredentials[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
		if err := scanner.Err(); err != nil {
			panic("load test credentials: " + err.Error())
		}
	})
}

func testCredential(key string) string {
	loadTestCredentials()
	value, ok := testCredentials[key]
	if !ok {
		panic("unknown test credential key: " + key)
	}
	return value
}

func testGeneratedSecret() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
