package conjurapi

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// versionMockServer reports version from /info and answers every other
// request with 200, or with a 426 version mismatch (optionally naming the
// current version in the Upgrade header) when mismatch says so. It records
// the Contract-Version and body of each of those requests.
type versionMockServer struct {
	client *Client

	mu       sync.Mutex
	version  string
	mismatch func(pin string) (refuse bool, hint string)
	pins     []string
	bodies   []string
	infoHits int
}

func newVersionMockServer(t *testing.T, environment EnvironmentType, version string) *versionMockServer {
	t.Helper()
	m := &versionMockServer{version: version, mismatch: func(string) (bool, string) { return false, "" }}
	m.client = newAuthenticatedMockServer(t, environment, func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		switch r.URL.Path {
		case "/info":
			m.infoHits++
			fmt.Fprintf(w, `{"release":"13.0.0","services":{"possum":{"version":"%s"}}}`, m.version)
		case "/":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			pin := r.Header.Get(contractVersionHeader)
			body, _ := io.ReadAll(r.Body)
			m.pins = append(m.pins, pin)
			m.bodies = append(m.bodies, string(body))
			if refuse, hint := m.mismatch(pin); refuse {
				if hint != "" {
					w.Header().Set("Upgrade", hint)
				}
				w.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			w.Write([]byte(`{}`))
		}
	})
	return m
}

func (m *versionMockServer) set(f func(m *versionMockServer)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func (m *versionMockServer) stats() (infoHits int, pins []string, bodies []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.infoHits, append([]string(nil), m.pins...), append([]string(nil), m.bodies...)
}

// withConjurrc points CONJURRC at a new file holding contents, and sets c up
// as LoadConfig and NewClient would from it: saved is the server version the
// file holds, and saving a new one is allowed.
func withConjurrc(t *testing.T, c *Client, contents, saved string) string {
	t.Helper()
	conjurrc := filepath.Join(t.TempDir(), ".conjurrc")
	require.NoError(t, os.WriteFile(conjurrc, []byte(contents), 0600))
	t.Setenv("CONJURRC", conjurrc)

	c.config.ServerVersion = saved
	c.version = serverVersion{}
	if saved != "" {
		c.version.preload(saved)
	}
	return conjurrc
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return string(data)
}

func TestServerVersion_Saved(t *testing.T) {
	t.Run("a retrieved version is saved to .conjurrc", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0-11")
		conjurrc := withConjurrc(t, m.client, "account: conjur\n", "")

		_, err := m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)
		assert.Equal(t, "account: conjur\nserver_version: 1.29.0-11\n", readFile(t, conjurrc))
	})

	t.Run("persisting rewrites the file as read from disk, not the env-merged runtime config", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0")
		conjurrc := withConjurrc(t, m.client, "account: conjur\n", "")
		m.client.config.Proxy = "http://env-proxy.example.com" // simulates a runtime Config merged from the environment

		_, err := m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)
		assert.Equal(t, "account: conjur\nserver_version: 1.29.0\n", readFile(t, conjurrc), "the file keeps what's on disk, not c.config's env-merged proxy")
	})

	t.Run("persisting round-trips the legacy Python-CLI key names instead of dropping them", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0")
		conjurrc := withConjurrc(t, m.client, "conjur_url: https://conjur.example.com\nconjur_account: conjur\n", "")

		_, err := m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)
		assert.Equal(t, "account: conjur\nappliance_url: https://conjur.example.com\nserver_version: 1.29.0\n", readFile(t, conjurrc),
			"appliance_url/account survive under their canonical keys, not silently dropped")
	})

	t.Run("a saved version spares the lookup", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0")
		conjurrc := withConjurrc(t, m.client, "server_version: 1.29.0\n", "1.29.0")

		_, err := m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 0, infoHits)
		assert.Equal(t, []string{"1.29.0"}, pins, "the saved version is pinned")
		assert.Equal(t, "server_version: 1.29.0\n", readFile(t, conjurrc))
	})

	t.Run("a saved version too old for a call is refused without checking the server", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0") // the live server is actually new enough
		withConjurrc(t, m.client, "server_version: 1.28.0\n", "1.28.0")

		for range 2 {
			_, err := m.client.V2().ReadBranch("data/apps")
			var target *contract.FeatureNotSupportedError
			require.ErrorAs(t, err, &target, "the saved version is trusted outright, even though the server was upgraded since")
		}

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 0, infoHits)
		assert.Empty(t, pins)
	})

	t.Run("a platform refusal keeps the saved version", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0")
		withConjurrc(t, m.client, "server_version: 1.29.0\n", "1.29.0")

		_, err := m.client.V2().GetWorkload("data/app")
		assert.EqualError(t, err, "Workload API is not supported in Idira Secrets Manager/Conjur OSS")
		_, err = m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)

		infoHits, _, _ := m.stats()
		assert.Equal(t, 0, infoHits)
	})

	t.Run("CapabilityStatus and VerifyMinServerVersion trust the saved version too, not the live server", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0") // the live server is actually new enough
		withConjurrc(t, m.client, "server_version: 1.26.0\n", "1.26.0")
		assert.Equal(t, contract.StatusUnsupported, m.client.CapabilityStatus(contract.CapabilityBranchesV2))

		m = newVersionMockServer(t, EnvironmentSH, "1.29.0")
		withConjurrc(t, m.client, "server_version: 1.26.0\n", "1.26.0")
		assert.Error(t, m.client.VerifyMinServerVersion("1.29.0"))

		infoHits, _, _ := m.stats()
		assert.Equal(t, 0, infoHits)
	})

	t.Run("nothing is saved if there's no .conjurrc to update", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.29.0")
		conjurrc := withConjurrc(t, m.client, "account: conjur\n", "")
		require.NoError(t, os.Remove(conjurrc))

		_, err := m.client.V2().ReadBranch("data/apps")
		require.NoError(t, err)
		_, statErr := os.Stat(conjurrc)
		assert.True(t, os.IsNotExist(statErr), "no file is created just to save the version")
	})

	t.Run("a version the checks can't use isn't saved", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "0.0.dev")
		conjurrc := withConjurrc(t, m.client, "account: conjur\n", "")

		_, err := m.client.V2().ReadBranch("data/apps")
		assert.Error(t, err)
		assert.Equal(t, "account: conjur\n", readFile(t, conjurrc))
	})

	t.Run("NewClient starts from the saved version, except on SaaS", func(t *testing.T) {
		config := Config{Account: "conjur", ApplianceURL: "https://conjur.example.com", Environment: EnvironmentSH, ServerVersion: "1.29.0"}
		c, err := NewClient(config)
		require.NoError(t, err)
		assert.Equal(t, "1.29.0", c.version.known())

		config.Environment = EnvironmentSaaS
		c, err = NewClient(config)
		require.NoError(t, err)
		assert.Empty(t, c.version.known())
	})
}

func TestSubmitRequest_VersionMismatch(t *testing.T) {
	newBranchRequest := func(t *testing.T, c *Client, body io.Reader) *http.Request {
		req, err := http.NewRequest(http.MethodPost, c.config.ApplianceURL+"/branches/conjur", body)
		require.NoError(t, err)
		return req
	}

	t.Run("a stale pin is refreshed and the request resent once", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.30.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(pin string) (bool, string) { return pin == "1.29.0", "" } })
		conjurrc := withConjurrc(t, m.client, "server_version: 1.29.0\n", "1.29.0")

		resp, err := m.client.SubmitRequest(newBranchRequest(t, m.client, strings.NewReader(`{"name":"apps"}`)))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		infoHits, pins, bodies := m.stats()
		assert.Equal(t, 1, infoHits, "no hint was given, so the fresh version is fetched")
		assert.Equal(t, []string{"1.29.0", "1.30.0"}, pins)
		assert.Equal(t, []string{`{"name":"apps"}`, `{"name":"apps"}`}, bodies, "the retry resends the body")
		assert.Equal(t, "server_version: 1.30.0\n", readFile(t, conjurrc))
	})

	t.Run("a stale pin's refusal naming the current version spares the lookup", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.30.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(pin string) (bool, string) { return pin == "1.29.0", "1.30.0" } })
		conjurrc := withConjurrc(t, m.client, "server_version: 1.29.0\n", "1.29.0")

		resp, err := m.client.SubmitRequest(newBranchRequest(t, m.client, strings.NewReader(`{"name":"apps"}`)))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 0, infoHits, "the hinted version is used directly")
		assert.Equal(t, []string{"1.29.0", "1.30.0"}, pins)
		assert.Equal(t, "server_version: 1.30.0\n", readFile(t, conjurrc), "the hinted version is still persisted")
	})

	t.Run("an unparseable hint falls back to a lookup instead of poisoning the cache", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.30.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(pin string) (bool, string) { return pin == "1.29.0", "not-a-version" } })
		conjurrc := withConjurrc(t, m.client, "server_version: 1.29.0\n", "1.29.0")

		resp, err := m.client.SubmitRequest(newBranchRequest(t, m.client, strings.NewReader(`{"name":"apps"}`)))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 1, infoHits, "the unparseable hint is discarded, so the real version is fetched")
		assert.Equal(t, []string{"1.29.0", "1.30.0"}, pins)
		assert.Equal(t, "server_version: 1.30.0\n", readFile(t, conjurrc))
	})

	t.Run("a second mismatch is returned instead of retrying again", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.30.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(string) (bool, string) { return true, "" } })
		withConjurrc(t, m.client, "", "1.29.0")

		resp, err := m.client.SubmitRequest(newBranchRequest(t, m.client, nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)

		_, pins, _ := m.stats()
		assert.Equal(t, []string{"1.29.0", "1.30.0"}, pins)
	})

	t.Run("the retry is refused if the current version doesn't support the request", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.28.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(pin string) (bool, string) { return pin == "1.29.0", "" } })
		withConjurrc(t, m.client, "", "1.29.0")

		_, err := m.client.SubmitRequest(newBranchRequest(t, m.client, nil))
		var target *contract.FeatureNotSupportedError
		require.ErrorAs(t, err, &target)
		assert.Equal(t, "Branch API is not supported in Idira Secrets Manager versions older than 1.29.0", err.Error())

		_, pins, _ := m.stats()
		assert.Len(t, pins, 1, "the retry isn't sent")
	})

	t.Run("a request whose body can't be resent gets the mismatch, and the stale version is dropped from memory", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.30.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(pin string) (bool, string) { return pin == "1.29.0", "" } })
		conjurrc := withConjurrc(t, m.client, "account: conjur\nserver_version: 1.29.0\n", "1.29.0")

		resp, err := m.client.SubmitRequest(newBranchRequest(t, m.client, struct{ io.Reader }{strings.NewReader("{}")}))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
		assert.Empty(t, m.client.version.known())
		assert.Equal(t, "account: conjur\nserver_version: 1.29.0\n", readFile(t, conjurrc), "the file isn't touched unless a fetch or hint actually succeeds")
	})

	t.Run("a mismatch code without a pin isn't retried", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.24.0")
		m.set(func(m *versionMockServer) { m.mismatch = func(string) (bool, string) { return true, "" } })

		// An ungated route, so nothing looks the version up to pin.
		req, err := http.NewRequest(http.MethodGet, m.client.config.ApplianceURL+"/secrets/conjur/variable/data%2Fdb", nil)
		require.NoError(t, err)
		resp, err := m.client.SubmitRequest(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 0, infoHits)
		assert.Equal(t, []string{""}, pins)
	})

	t.Run("an unknown version isn't looked up just to pin it", func(t *testing.T) {
		m := newVersionMockServer(t, EnvironmentSH, "1.24.0")

		_, err := m.client.RetrieveSecret("data/db")
		require.NoError(t, err)

		infoHits, pins, _ := m.stats()
		assert.Equal(t, 0, infoHits)
		assert.Equal(t, []string{""}, pins)
	})
}

func TestIsVersionMismatch(t *testing.T) {
	newResponse := func(status int, upgrade string) *http.Response {
		h := http.Header{}
		if upgrade != "" {
			h.Set("Upgrade", upgrade)
		}
		return &http.Response{StatusCode: status, Header: h}
	}

	mismatch, hinted := isVersionMismatch(newResponse(http.StatusUpgradeRequired, "1.30.0"))
	assert.True(t, mismatch)
	assert.Equal(t, "1.30.0", hinted)

	mismatch, hinted = isVersionMismatch(newResponse(http.StatusUpgradeRequired, ""))
	assert.True(t, mismatch)
	assert.Empty(t, hinted)

	mismatch, _ = isVersionMismatch(newResponse(http.StatusConflict, ""))
	assert.False(t, mismatch, "409 is a real Conjur response code (e.g. policy conflicts), not a version signal")
}

func TestLoadConfig_ServerVersion(t *testing.T) {
	load := func(t *testing.T, conjurrcContents string, env map[string]string) Config {
		t.Helper()
		e := ClearEnv()
		t.Cleanup(e.RestoreEnv)

		conjurrc := filepath.Join(t.TempDir(), ".conjurrc")
		require.NoError(t, os.WriteFile(conjurrc, []byte(conjurrcContents), 0600))
		t.Setenv("CONJURRC", conjurrc)
		for k, v := range env {
			t.Setenv(k, v)
		}

		config, err := LoadConfig()
		require.NoError(t, err)
		return config
	}
	contents := "appliance_url: https://conjur.example.com\naccount: conjur\nenvironment: self-hosted\nserver_version: 1.23.0\n"

	t.Run("reads the saved version", func(t *testing.T) {
		config := load(t, contents, nil)
		assert.Equal(t, "1.23.0", config.ServerVersion)
	})

	t.Run("ignores the saved version for an appliance URL set in the environment", func(t *testing.T) {
		config := load(t, contents, map[string]string{"CONJUR_APPLIANCE_URL": "https://other.example.com"})
		assert.Empty(t, config.ServerVersion)
	})

	t.Run("doesn't read the legacy version key as the server version", func(t *testing.T) {
		config := load(t, "appliance_url: https://conjur.example.com\naccount: conjur\nenvironment: self-hosted\nversion: 5\n", nil)
		assert.Empty(t, config.ServerVersion)
	})
}

// AddToConjurRc is a one-time default-backfill mechanism (see
// Config.applyDefaults), append-only by design: it's never meant to update a
// value that's rewritten repeatedly over a client's life, unlike the server
// version, which is a normal (if unusual) Config field persisted by
// rewriting the whole file (see Client.persistServerVersion).
func TestAddToConjurRc(t *testing.T) {
	testCases := []struct {
		name     string
		existing string
		want     string
	}{
		{"appends a new key", "account: conjur\n", "account: conjur\nenvironment: cloud\n"},
		{"appends after a last line with no newline", "account: conjur", "account: conjurenvironment: cloud\n"},
		{"appends even if the key is already present", "environment: self-hosted\n", "environment: self-hosted\nenvironment: cloud\n"},
		{"creates the file", "", "environment: cloud\n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conjurrc := filepath.Join(t.TempDir(), ".conjurrc")
			if tc.existing != "" {
				require.NoError(t, os.WriteFile(conjurrc, []byte(tc.existing), 0600))
			}
			t.Setenv("CONJURRC", conjurrc)

			(&Config{}).AddToConjurRc("environment", "cloud")
			assert.Equal(t, tc.want, readFile(t, conjurrc))
		})
	}
}
