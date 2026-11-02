package spiffe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestJWTFetchDeadlineIsDistinctFromUnavailable(t *testing.T) {
	t.Setenv(envSpiffeEndpointSocket, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	fetch := func(ctx context.Context, _ string) ([]*jwtsvid.SVID, error) {
		<-ctx.Done() // wedged Workload API: never answers
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	_, _, err := fetchJWTSVIDFromWorkloadAPI(ctx, "conjur", fetch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not respond within the deadline")
	assert.NotContains(t, err.Error(), "still unavailable")
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || status.Code(errors.Unwrap(err)) == codes.DeadlineExceeded)
}

func TestWorkloadAPITimeout(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 15 * time.Second, "20": 20 * time.Second, "2s": 2 * time.Second,
		"bogus": 15 * time.Second, "-1": 15 * time.Second,
	} {
		t.Setenv(envConjurSpiffeTimeout, in)
		assert.Equal(t, want, workloadAPITimeout(), "CONJUR_SPIFFE_TIMEOUT=%q", in)
	}
}
