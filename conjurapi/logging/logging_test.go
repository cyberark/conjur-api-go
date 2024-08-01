package logging

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	t.Run("CONJURAPI_LOG is not set", func(t *testing.T) {
		os.Unsetenv("CONJURAPI_LOG")
		initLogger()
		// Defaults to Stderr with Info level
		assert.Equal(t, os.Stderr, ApiLog.Out)
		assert.Equal(t, logrus.InfoLevel, ApiLog.Level)
	})

	t.Run("stdout", func(t *testing.T) {
		os.Setenv("CONJURAPI_LOG", "stdout")
		initLogger()
		assert.Equal(t, os.Stdout, ApiLog.Out)
		assert.Equal(t, logrus.DebugLevel, ApiLog.Level)
	})

	t.Run("stderr", func(t *testing.T) {
		os.Setenv("CONJURAPI_LOG", "stderr")
		initLogger()
		assert.Equal(t, os.Stderr, ApiLog.Out)
		assert.Equal(t, logrus.DebugLevel, ApiLog.Level)
	})

	t.Run("file", func(t *testing.T) {
		tmpFile := t.TempDir() + "/logfile.log"
		os.Setenv("CONJURAPI_LOG", tmpFile)
		initLogger()
		assertFileExists(t, tmpFile)
		assert.Equal(t, logrus.DebugLevel, ApiLog.Level)
	})

	t.Run("file in nonexistent directory", func(t *testing.T) {
		tmpFile := "/nonexistent/logfile.log"
		fatalCalled := false

		// Mock the logrus.Fatalf function
		fatalFn = func(format string, args ...interface{}) {
			fatalCalled = true
			assert.Contains(t, format, "Failed to open")
			assert.Len(t, args, 2)
			assert.Equal(t, args[0], tmpFile)
			assert.Contains(t, args[1], "no such file or directory")
		}

		os.Setenv("CONJURAPI_LOG", tmpFile)
		initLogger()
		assert.True(t, fatalCalled)
	})
}

func assertFileExists(t *testing.T, filePath string) {
	_, err := os.Stat(filePath)
	assert.False(t, os.IsNotExist(err), "Expected file to exist: %s", filePath)
}

func TestApiLog(t *testing.T) {
	// Redirect logrus output to a buffer
	var buf bytes.Buffer
	ApiLog = logrus.New()
	ApiLog.Out = &buf
	ApiLog.Level = logrus.DebugLevel

	// Test logging
	ApiLog.Debug("Debug message")
	ApiLog.Info("Info message")
	ApiLog.Warn("Warning message")
	ApiLog.Error("Error message")

	// Read the buffer contents
	logOutput, err := io.ReadAll(&buf)
	assert.NoError(t, err)

	assert.Contains(t, string(logOutput), "Debug message")
	assert.Contains(t, string(logOutput), "Info message")
	assert.Contains(t, string(logOutput), "Warning message")
	assert.Contains(t, string(logOutput), "Error message")
}
