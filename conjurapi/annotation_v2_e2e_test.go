package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAnnotated creates a branch data/test-sdk-annotation-<time> holding a
// group and a workload, and returns the identifier of each kind's resource.
// Cleanup deletes the branch and everything under it.
func newTestAnnotated(t *testing.T) (conjur *ClientV2, ids map[AnnotationKind]string) {
	t.Helper()
	utils, err := NewTestUtils(&Config{})
	require.NoError(t, err)
	client := utils.Client()
	if !client.config.IsSaaS() {
		t.Skip("Skipping off Secrets Manager SaaS: workload and branch annotations are SaaS-only")
	}
	conjur = client.V2()

	name := fmt.Sprintf("test-sdk-annotation-%d", time.Now().UnixNano())
	_, err = conjur.CreateBranch(Branch{Branch: "data", Name: name})
	require.NoError(t, err)
	branch := "data/" + name
	t.Cleanup(func() {
		err := conjur.DeleteBranch(branch)
		var conjurErr *response.ConjurError
		if !errors.As(err, &conjurErr) || conjurErr.Code != http.StatusNotFound {
			assert.NoError(t, err)
		}
	})

	_, err = conjur.CreateGroup(Group{Branch: branch, Name: "grp"})
	require.NoError(t, err)
	_, err = conjur.CreateWorkload(Workload{
		Branch:           branch,
		Name:             "wl1",
		AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
	})
	require.NoError(t, err)

	ids = map[AnnotationKind]string{
		AnnotationKindBranch:   branch,
		AnnotationKindGroup:    branch + "/grp",
		AnnotationKindWorkload: branch + "/wl1",
	}
	for _, kind := range SupportedAnnotationKinds() {
		require.Contains(t, ids, kind, "no test resource for this kind")
	}
	return conjur, ids
}

func requireNotFound(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	var conjurErr *response.ConjurError
	require.ErrorAs(t, err, &conjurErr, msgAndArgs...)
	assert.Equal(t, http.StatusNotFound, conjurErr.Code, msgAndArgs...)
}

func TestClientV2_Annotations_SetGetListDelete(t *testing.T) {
	conjur, ids := newTestAnnotated(t)

	for _, kind := range SupportedAnnotationKinds() {
		t.Run(string(kind), func(t *testing.T) {
			id := ids[kind]

			// Each set sends only its own annotation and the server merges
			// it, so b keeps a, and setting a again replaces only a.
			require.NoError(t, conjur.SetAnnotation(kind, id, "a", "1"))
			require.NoError(t, conjur.SetAnnotation(kind, id, "b", "2"))
			require.NoError(t, conjur.SetAnnotation(kind, id, "a", "1 changed"))

			got, err := conjur.ListAnnotations(kind, id)
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"a": "1 changed", "b": "2"}, got)

			value, err := conjur.GetAnnotation(kind, id, "a")
			require.NoError(t, err)
			assert.Equal(t, "1 changed", value)

			require.NoError(t, conjur.DeleteAnnotation(kind, id, "a"))
			got, err = conjur.ListAnnotations(kind, id)
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"b": "2"}, got)
		})
	}
}

func TestClientV2_Annotations_NamesNeedingEscaping(t *testing.T) {
	conjur, ids := newTestAnnotated(t)
	names := []string{
		"x/y", "x:y", "x y", "x%y", "x?y", "x#y", "pl+us", "ünï", "...", "a/..",
		// Sent with a literal slash, this would be the resource's
		// permissions route.
		"permissions/user/bob",
	}

	for _, kind := range SupportedAnnotationKinds() {
		t.Run(string(kind), func(t *testing.T) {
			id := ids[kind]
			kindNames := names
			if kind == AnnotationKindGroup {
				// And this the group's member route.
				kindNames = append(slices.Clone(names), "members/user/bob")
			}

			for _, name := range kindNames {
				require.NoError(t, conjur.SetAnnotation(kind, id, name, "v"), name)
				value, err := conjur.GetAnnotation(kind, id, name)
				require.NoError(t, err, name)
				assert.Equal(t, "v", value, name)

				require.NoError(t, conjur.DeleteAnnotation(kind, id, name), name)
				_, err = conjur.GetAnnotation(kind, id, name)
				requireNotFound(t, err, name)
			}

			// No delete reached anything but its own annotation.
			got, err := conjur.ListAnnotations(kind, id)
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestClientV2_Annotations_NotFound(t *testing.T) {
	conjur, ids := newTestAnnotated(t)
	// Under the test's own branch, so nothing else on the server is touched.
	missing := ids[AnnotationKindBranch] + "/missing"

	for _, kind := range SupportedAnnotationKinds() {
		t.Run(string(kind), func(t *testing.T) {
			id := ids[kind]

			_, err := conjur.GetAnnotation(kind, id, "never-set")
			requireNotFound(t, err, "get of a missing annotation")
			err = conjur.DeleteAnnotation(kind, id, "never-set")
			requireNotFound(t, err, "delete of a missing annotation")
			assert.Contains(t, err.Error(), "Annotation 'never-set' was not found")

			requireNotFound(t, conjur.SetAnnotation(kind, missing, "a", "v"), "set on a missing resource")
			_, err = conjur.ListAnnotations(kind, missing)
			requireNotFound(t, err, "list on a missing resource")
			_, err = conjur.GetAnnotation(kind, missing, "a")
			requireNotFound(t, err, "get on a missing resource")
			requireNotFound(t, conjur.DeleteAnnotation(kind, missing, "a"), "delete on a missing resource")
		})
	}
}

// The SDK's own checks stop at the server's limits, not short of them, and the
// cap only the server can check reaches the caller as its 422.
func TestClientV2_Annotations_ServerLimits(t *testing.T) {
	conjur, ids := newTestAnnotated(t)

	for _, kind := range SupportedAnnotationKinds() {
		t.Run(string(kind), func(t *testing.T) {
			id := ids[kind]

			// The limits count characters, not bytes.
			name := strings.Repeat("ü", maxAnnotationNameLength)
			value := strings.Repeat("ü", maxAnnotationValueLength)
			require.NoError(t, conjur.SetAnnotation(kind, id, name, value))
			got, err := conjur.GetAnnotation(kind, id, name)
			require.NoError(t, err)
			assert.Equal(t, value, got)

			for i := 2; i <= 20; i++ {
				require.NoError(t, conjur.SetAnnotation(kind, id, fmt.Sprintf("k%d", i), "v"))
			}
			err = conjur.SetAnnotation(kind, id, "k21", "v")
			var conjurErr *response.ConjurError
			require.ErrorAs(t, err, &conjurErr)
			assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
			assert.Contains(t, err.Error(), "Cannot have more than 20 annotations")

			// At the cap an existing annotation can still change.
			require.NoError(t, conjur.SetAnnotation(kind, id, "k2", "changed"))
		})
	}
}

func TestClientV2_Annotations_WorkloadReservedNames(t *testing.T) {
	conjur, ids := newTestAnnotated(t)

	t.Run("are ordinary names on a group and a branch", func(t *testing.T) {
		for _, kind := range []AnnotationKind{AnnotationKindGroup, AnnotationKindBranch} {
			require.NoError(t, conjur.SetAnnotation(kind, ids[kind], "type", "v"), kind)
			require.NoError(t, conjur.SetAnnotation(kind, ids[kind], "authn-jwt/prod", "v"), kind)
			got, err := conjur.ListAnnotations(kind, ids[kind])
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"type": "v", "authn-jwt/prod": "v"}, got, kind)
		}
	})

	t.Run("are refused on a workload", func(t *testing.T) {
		id := ids[AnnotationKindWorkload]

		err := conjur.SetAnnotation(AnnotationKindWorkload, id, "type", "v")
		assert.ErrorContains(t, err, "reserved on workloads")
		// Only the exact names are reserved.
		require.NoError(t, conjur.SetAnnotation(AnnotationKindWorkload, id, "TYPE", "v"))

		// The server refuses to delete them, so the workload keeps its login.
		err = conjur.DeleteAnnotation(AnnotationKindWorkload, id, "authn/api-key")
		var conjurErr *response.ConjurError
		require.ErrorAs(t, err, &conjurErr)
		assert.Equal(t, http.StatusUnprocessableEntity, conjurErr.Code)
		assert.Contains(t, err.Error(), "Cannot delete protected annotation")

		workload, err := conjur.GetWorkload(id)
		require.NoError(t, err)
		require.Len(t, workload.AuthnDescriptors, 1)
		assert.Equal(t, "api_key", workload.AuthnDescriptors[0].Type)
		assert.Equal(t, map[string]string{"TYPE": "v"}, workload.Annotations)
	})
}

// Each set sends only its own annotation and the server merges it, so
// concurrent sets of different names all survive.
func TestClientV2_Annotations_ConcurrentSets(t *testing.T) {
	conjur, ids := newTestAnnotated(t)

	for _, kind := range SupportedAnnotationKinds() {
		t.Run(string(kind), func(t *testing.T) {
			id := ids[kind]
			want := map[string]string{}
			errs := make([]error, 5)
			var wg sync.WaitGroup
			for i := range errs {
				name := fmt.Sprintf("c%d", i)
				want[name] = "v"
				wg.Go(func() { errs[i] = conjur.SetAnnotation(kind, id, name, "v") })
			}
			wg.Wait()
			for _, err := range errs {
				require.NoError(t, err)
			}

			got, err := conjur.ListAnnotations(kind, id)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

// The annotation methods and each resource's own annotations field read and
// write the same annotations.
func TestClientV2_Annotations_MatchResourceField(t *testing.T) {
	conjur, ids := newTestAnnotated(t)
	parent := ids[AnnotationKindBranch]

	t.Run("annotations given at create are listed", func(t *testing.T) {
		made := map[string]string{"made": "at create"}
		_, err := conjur.CreateBranch(Branch{Branch: parent, Name: "inline-branch", Annotations: made})
		require.NoError(t, err)
		_, err = conjur.CreateGroup(Group{Branch: parent, Name: "inline-group", Annotations: made})
		require.NoError(t, err)
		_, err = conjur.CreateWorkload(Workload{
			Branch:           parent,
			Name:             "inline-workload",
			Annotations:      made,
			AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
		})
		require.NoError(t, err)

		inline := map[AnnotationKind]string{
			AnnotationKindBranch:   parent + "/inline-branch",
			AnnotationKindGroup:    parent + "/inline-group",
			AnnotationKindWorkload: parent + "/inline-workload",
		}
		for _, kind := range SupportedAnnotationKinds() {
			got, err := conjur.ListAnnotations(kind, inline[kind])
			require.NoError(t, err, kind)
			assert.Equal(t, made, got, kind)
		}
	})

	t.Run("annotations set one at a time are in the resource read", func(t *testing.T) {
		for _, kind := range SupportedAnnotationKinds() {
			require.NoError(t, conjur.SetAnnotation(kind, ids[kind], "set", "by SetAnnotation"), kind)
		}
		want := map[string]string{"set": "by SetAnnotation"}

		branch, err := conjur.ReadBranch(ids[AnnotationKindBranch])
		require.NoError(t, err)
		assert.Equal(t, want, branch.Annotations)

		group, err := conjur.ReadGroup(ids[AnnotationKindGroup])
		require.NoError(t, err)
		assert.Equal(t, want, group.Annotations)

		workload, err := conjur.GetWorkload(ids[AnnotationKindWorkload])
		require.NoError(t, err)
		assert.Equal(t, want, workload.Annotations)
	})
}
