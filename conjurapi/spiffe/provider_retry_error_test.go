package spiffe

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestJWTRetryExhaustedKeepsUnderlyingError(t *testing.T) {
	orig := retryInitial
	retryInitial = time.Millisecond
	t.Cleanup(func() { retryInitial = orig })
	t.Setenv(envSpiffeEndpointSocket, "")

	fetch := func(context.Context, string) ([]*jwtsvid.SVID, error) {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	_, _, err := fetchJWTSVIDFromWorkloadAPI(context.Background(), "conjur", fetch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still unavailable after")
	assert.Contains(t, err.Error(), "connection refused")
}
