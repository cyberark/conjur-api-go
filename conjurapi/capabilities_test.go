package conjurapi

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capabilityMockServer reports version from /info (or fails /info and the root
// endpoint when version is empty) and answers every other request with 200. It
// counts /info probes and other requests.
type capabilityMockServer struct {
	client   *ClientV2
	infoHits atomic.Int32
	apiHits  atomic.Int32
}

func newCapabilityMockServer(t *testing.T, environment EnvironmentType, version string) *capabilityMockServer {
	t.Helper()
	m := &capabilityMockServer{}
	client := newAuthenticatedMockServer(t, environment, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/info":
			m.infoHits.Add(1)
			if version == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, `{"release":"13.0.0","services":{"possum":{"version":"%s"}}}`, version)
		case r.URL.Path == "/":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			m.apiHits.Add(1)
			w.Write([]byte(`{}`))
		}
	})
	m.client = &ClientV2{client}
	return m
}

func TestSubmitRequest_Capabilities(t *testing.T) {
	t.Run("self-hosted too old: blocked before sending, including via a request builder", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "1.28.0")

		req, err := m.client.ReadBranchRequest("data/apps")
		require.NoError(t, err)
		_, err = m.client.SubmitRequest(req)
		var target *contract.FeatureNotSupportedError
		require.ErrorAs(t, err, &target)
		assert.EqualError(t, err, "Branch API is not supported in Idira Secrets Manager versions older than 1.29.0")

		_, err = m.client.ReadBranch("data/apps")
		require.ErrorAs(t, err, &target)

		assert.Equal(t, int32(0), m.apiHits.Load(), "a gated request must never reach the server")
		assert.Equal(t, int32(1), m.infoHits.Load(), "the server version is retrieved once, then cached")
	})

	t.Run("self-hosted new enough: sent", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "1.29.0")

		_, err := m.client.ReadBranch("data/apps")
		require.NoError(t, err)
		_, err = m.client.ReadGroup("data/team")
		require.NoError(t, err)

		assert.Equal(t, int32(2), m.apiHits.Load())
		assert.Equal(t, int32(1), m.infoHits.Load())
	})

	t.Run("self-hosted with version unavailable: blocked", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "")

		_, err := m.client.ReadGroup("data/team")
		var target *contract.FeatureNotSupportedError
		require.ErrorAs(t, err, &target)
		assert.Error(t, target.Err, "the lookup failure is kept")
		assert.ErrorContains(t, err, "Group API is not supported in Idira Secrets Manager versions older than 1.29.0 (server version unavailable: ")
		assert.Equal(t, int32(0), m.apiHits.Load())
	})

	t.Run("self-hosted: SaaS-only API blocked without retrieving the version", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "1.23.0")

		_, err := m.client.GetWorkload("data/app")
		assert.EqualError(t, err, "Workload API is not supported in Idira Secrets Manager/Conjur OSS")
		assert.Equal(t, int32(0), m.apiHits.Load())
		assert.Equal(t, int32(0), m.infoHits.Load())
	})

	t.Run("SaaS: version-gated API sent without retrieving the version", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSaaS, "1.0.0")

		_, err := m.client.ReadGroup("data/team")
		require.NoError(t, err)
		assert.Equal(t, int32(1), m.apiHits.Load())
		assert.Equal(t, int32(0), m.infoHits.Load())
	})

	t.Run("SaaS: SaaS-unsupported API blocked", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSaaS, "")

		_, err := m.client.FetchPolicy("root", false, 0, 0)
		assert.EqualError(t, err, "Policy Fetch is not supported in Idira Secrets Manager, SaaS")
		assert.Equal(t, int32(0), m.apiHits.Load())
	})

	t.Run("self-hosted: v1 IDs containing a gated route's name are not gated", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "1.0.0")

		for _, id := range []string{"data/workloads/db", "data/branches/x", "data/authenticators/k"} {
			_, err := m.client.RetrieveSecret(id)
			require.NoError(t, err, id)
		}
		_, err := m.client.Resource("conjur:variable:data/authenticators/k")
		require.NoError(t, err)

		assert.Equal(t, int32(4), m.apiHits.Load())
		assert.Equal(t, int32(0), m.infoHits.Load())
	})
}

// Run with -race: the version cache is shared by every request on a client.
// This calls the check SubmitRequest makes, rather than SubmitRequest itself,
// so the test only covers the version cache and not token refresh.
func TestCheckRequestCapability_ConcurrentVersionLookup(t *testing.T) {
	m := newCapabilityMockServer(t, EnvironmentSH, "1.29.0")

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			req, err := m.client.ReadGroupRequest("data/team")
			if assert.NoError(t, err) {
				assert.NoError(t, m.client.checkRequestCapability(req))
			}
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), m.infoHits.Load(), "concurrent callers share one version lookup")
}

func TestCheckRequestCapability_BasePath(t *testing.T) {
	c := &Client{config: Config{ApplianceURL: "https://conjur.example.com/prefix/", Environment: EnvironmentSH, Account: "conjur"}}
	c.version.preload("1.0.0")

	gated, err := http.NewRequest(http.MethodGet, "https://conjur.example.com/prefix/branches/conjur", nil)
	require.NoError(t, err)
	assert.Error(t, c.checkRequestCapability(gated), "the route is matched relative to the base path")

	outside, err := http.NewRequest(http.MethodGet, "https://conjur.example.com/branches/conjur", nil)
	require.NoError(t, err)
	assert.NoError(t, c.checkRequestCapability(outside), "a request outside the base path isn't an API route")

	sibling, err := http.NewRequest(http.MethodGet, "https://conjur.example.com/prefixbranches/conjur", nil)
	require.NoError(t, err)
	assert.NoError(t, c.checkRequestCapability(sibling))
}

func TestClient_CapabilityStatus(t *testing.T) {
	t.Run("self-hosted", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "1.28.0")

		assert.Equal(t, contract.StatusUnsupported, m.client.CapabilityStatus(contract.CapabilityBranchesV2))
		assert.Equal(t, contract.StatusSupported, m.client.CapabilityStatus(contract.CapabilityLdapMappings))
		assert.Equal(t, contract.StatusUnsupported, m.client.CapabilityStatus(contract.CapabilityWorkloadV2))
	})

	t.Run("self-hosted with version unavailable", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSH, "")

		assert.Equal(t, contract.StatusUnknown, m.client.CapabilityStatus(contract.CapabilityBranchesV2))
		assert.Equal(t, contract.StatusUnknown, m.client.CapabilityStatus(contract.CapabilityPublicKeys))
		assert.Equal(t, contract.StatusUnsupported, m.client.CapabilityStatus(contract.CapabilityWorkloadV2), "platform restrictions don't need the version")
	})

	t.Run("SaaS", func(t *testing.T) {
		m := newCapabilityMockServer(t, EnvironmentSaaS, "")

		assert.Equal(t, contract.StatusSupported, m.client.CapabilityStatus(contract.CapabilityWorkloadV2))
		assert.Equal(t, contract.StatusUnsupported, m.client.CapabilityStatus(contract.CapabilityPolicyDryRun))
		assert.Equal(t, int32(0), m.infoHits.Load())
	})
}

func TestSWA_Capability(t *testing.T) {
	m := newCapabilityMockServer(t, EnvironmentSH, "1.23.0")

	_, err := m.client.SWA()
	assert.EqualError(t, err, "SWA API is not supported in Idira Secrets Manager/Conjur OSS")
	assert.Equal(t, int32(0), m.infoHits.Load())
}
