package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBranches creates a branch, data/test-sdk-branch-<time>, with count
// child branches, c0, c1, ..., and deletes it, and everything under it, when
// the test ends.
func newTestBranches(t *testing.T, count int) (conjur *Client, parent string, children []string) {
	t.Helper()
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	conjur = utils.Client()
	SkipIfUnsupported(t, conjur, contract.CapabilityBranchesV2)

	name := fmt.Sprintf("test-sdk-branch-%d", time.Now().UnixNano())
	_, err = conjur.V2().CreateBranch(Branch{Branch: "data", Name: name})
	require.NoError(t, err)
	parent = "data/" + name
	t.Cleanup(func() {
		// A test may have deleted it already.
		err := conjur.V2().DeleteBranch(parent)
		var conjurErr *response.ConjurError
		if !errors.As(err, &conjurErr) || conjurErr.Code != http.StatusNotFound {
			assert.NoError(t, err)
		}
	})

	for i := range count {
		child := fmt.Sprintf("c%d", i)
		_, err := conjur.V2().CreateBranch(Branch{Branch: parent, Name: child})
		require.NoError(t, err)
		children = append(children, parent+"/"+child)
	}
	return conjur, parent, children
}

func TestClientV2_UpdateBranch(t *testing.T) {
	conjur, parent, _ := newTestBranches(t, 0)
	branch := Branch{Branch: "data", Name: strings.TrimPrefix(parent, "data/")}

	t.Run("Adds annotations without removing the others", func(t *testing.T) {
		branch.Annotations = map[string]string{"description": "kept by a patch"}
		_, err := conjur.V2().UpdateBranch(branch)
		require.NoError(t, err)

		branch.Annotations = map[string]string{"owner-team": "sdk"}
		got, err := conjur.V2().UpdateBranch(branch)
		require.NoError(t, err)
		assert.Equal(t, branch.Name, got.Name)
		assert.Equal(t, "data", got.Branch)
		assert.Equal(t, map[string]string{"description": "kept by a patch", "owner-team": "sdk"}, got.Annotations)
		if conjur.config.IsSaaS() {
			assert.NotEmpty(t, got.CreatedAt)
		}

		read, err := conjur.V2().ReadBranch(parent)
		require.NoError(t, err)
		assert.Equal(t, got.Annotations, read.Annotations)
	})

	t.Run("Rejects an owner with a 422 on SaaS", func(t *testing.T) {
		if !conjur.config.IsSaaS() {
			t.Skip("Self-Hosted can change a branch's owner")
		}

		_, err := conjur.V2().UpdateBranch(Branch{
			Branch: branch.Branch,
			Name:   branch.Name,
			Owner:  &Owner{Kind: "user", Id: os.Getenv("CONJUR_AUTHN_LOGIN")},
		})
		var conjurErr *response.ConjurError
		require.ErrorAs(t, err, &conjurErr)
		assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
		assert.Contains(t, err.Error(), "Unexpected parameters: owner")
	})
}

func TestClientV2_CreateBranch_DuplicateConflicts(t *testing.T) {
	conjur, parent, _ := newTestBranches(t, 0)

	_, err := conjur.V2().CreateBranch(Branch{Branch: "data", Name: strings.TrimPrefix(parent, "data/")})
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr)
	assert.Equal(t, http.StatusConflict, conjurErr.Code)
	assert.Contains(t, err.Error(), "already exists")
}

func TestClientV2_DeleteBranch_RemovesEverythingUnder(t *testing.T) {
	conjur, parent, children := newTestBranches(t, 1)
	_, err := conjur.V2().CreateStaticSecret(StaticSecret{Branch: children[0], Name: "secret", Value: "s3cr3t"})
	require.NoError(t, err)
	secretID := fmt.Sprintf("%s:variable:%s/secret", conjur.config.Account, children[0])

	// Neither the child branch nor the secret stops the delete.
	require.NoError(t, conjur.V2().DeleteBranch(parent))

	for _, branch := range []string{parent, children[0]} {
		_, err := conjur.V2().ReadBranch(branch)
		var conjurErr *response.ConjurError
		require.ErrorAs(t, err, &conjurErr, branch)
		assert.Equal(t, http.StatusNotFound, conjurErr.Code, branch)
	}
	exists, err := conjur.ResourceExists(secretID)
	require.NoError(t, err)
	assert.False(t, exists, "the secret under the branch is deleted too")
}

func TestClientV2_ReadBranches_PagesAddUp(t *testing.T) {
	if !isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
		t.Skip("Skipping SaaS branch paging test for on-prem")
	}
	conjur, _, children := newTestBranches(t, 3)

	// The list holds the tenant's other branches too, which other jobs may
	// change between calls, so only the test's own branches are compared.
	first, err := conjur.V2().ReadBranches(&BranchFilter{Limit: 1})
	require.NoError(t, err)
	require.GreaterOrEqual(t, first.Count, len(children))
	filter := &BranchFilter{Limit: max(1, first.Count/3)}

	var ids []string
	for calls := 0; ; calls++ {
		require.Less(t, calls, first.Count, "paging doesn't end")
		page, err := conjur.V2().ReadBranches(filter)
		require.NoError(t, err)
		for _, b := range page.Branches {
			ids = append(ids, b.Branch+"/"+b.Name)
		}
		if filter.Offset+len(page.Branches) >= page.Count {
			break
		}
		filter.Offset += len(page.Branches)
	}
	assert.Subset(t, ids, children)

	past := &BranchFilter{Limit: 1, Offset: first.Count + 1000}
	page, err := conjur.V2().ReadBranches(past)
	require.NoError(t, err)
	assert.Empty(t, page.Branches)
}
