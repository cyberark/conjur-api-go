package conjurapi

import (
	"net/http"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireWorkloadStatus requires err to be a *response.ConjurError with the
// given HTTP status.
func requireWorkloadStatus(t *testing.T, err error, status int, msgAndArgs ...any) {
	t.Helper()
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr, msgAndArgs...)
	require.Equal(t, status, conjurErr.Code, msgAndArgs...)
}

// TestClientV2_WorkloadListReplaceAndDescriptorDelete covers ListWorkloads,
// ReplaceWorkload, DeleteAuthnDescriptor and ListAuthnDescriptors against a real Conjur Cloud
// (SaaS) instance. Like TestClientV2_WorkloadLifecycle, it uses only api_key
// descriptors.
func TestClientV2_WorkloadListReplaceAndDescriptorDelete(t *testing.T) {
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)

	conjur := utils.Client().V2()
	if !conjur.config.IsSaaS() {
		t.Skip("Skipping off Secrets Manager SaaS: the workload API is SaaS-only")
	}

	_, err = utils.Setup(workloadTestPolicy)
	require.NoError(t, err)

	branch := utils.PolicyBranch()
	const workloadName = "api-go-workload-replace-test"
	identifier := branch + "/" + workloadName

	// Leftovers from an interrupted run would fail the create.
	_, _ = conjur.DeleteWorkload(identifier)

	_, err = conjur.CreateWorkload(Workload{
		Branch:           branch,
		Name:             workloadName,
		Annotations:      map[string]string{"team": "api-go-tests"},
		RestrictedTo:     []string{"127.0.0.1"},
		AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := conjur.DeleteWorkload(identifier); err != nil {
			t.Logf("failed to clean up workload %s: %s", identifier, err)
		}
	})

	t.Run("list pages through to the workload", func(t *testing.T) {
		first, err := conjur.ListWorkloads(&WorkloadFilter{Limit: 1})
		require.NoError(t, err)
		assert.Len(t, first.Workloads, 1, "limit=1 must return one workload")

		const pageSize = 100
		found := false
		for offset := 0; !found; offset += pageSize {
			page, err := conjur.ListWorkloads(&WorkloadFilter{Limit: pageSize, Offset: offset})
			require.NoError(t, err)
			for _, w := range page.Workloads {
				if w.Branch == branch && w.Name == workloadName {
					found = true
				}
			}
			if len(page.Workloads) < pageSize || offset+pageSize >= page.Count {
				break
			}
		}
		assert.True(t, found, "ListWorkloads did not return %s", identifier)
	})

	t.Run("replace clears the fields it leaves out", func(t *testing.T) {
		replaced, err := conjur.ReplaceWorkload(identifier, WorkloadFields{
			Annotations:      map[string]string{"replaced": "yes"},
			AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"replaced": "yes"}, replaced.Annotations, "PUT must drop the annotations it didn't send")
		assert.Empty(t, replaced.RestrictedTo, "PUT must clear restricted_to when it isn't sent")
	})

	t.Run("replace without a login method is rejected", func(t *testing.T) {
		_, err := conjur.ReplaceWorkload(identifier, WorkloadFields{
			Annotations: map[string]string{"replaced": "again"},
		})
		require.ErrorContains(t, err, "at least one authenticator")

		read, err := conjur.GetWorkload(identifier)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"replaced": "yes"}, read.Annotations, "a rejected replace must leave the workload unchanged")
	})

	t.Run("delete the api_key descriptor", func(t *testing.T) {
		require.NoError(t, conjur.DeleteAuthnDescriptor(identifier, AuthnDescriptor{Type: "api_key"}))

		descriptors, err := conjur.ListAuthnDescriptors(identifier)
		require.NoError(t, err)
		assert.Empty(t, descriptors.AuthnDescriptors)
		assert.Zero(t, descriptors.Count)
	})

	t.Run("delete a missing descriptor is not found", func(t *testing.T) {
		err := conjur.DeleteAuthnDescriptor(identifier, AuthnDescriptor{Type: "jwt", ServiceID: "api-go-missing"})
		requireWorkloadStatus(t, err, http.StatusNotFound)
	})
}
