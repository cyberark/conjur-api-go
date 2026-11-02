package spiffe

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An expired JWT-SVID is still returned: Conjur remains the verifier, and the
// caller only gets a warning plus a clearer error if Conjur rejects it.
func TestFetchJWTSVID_ExpiredSVIDIsStillReturned(t *testing.T) {
	t.Setenv(envSpiffeEndpointSocket, "")
	id := spiffeid.RequireFromString("spiffe://example.org/workload")
	for name, expiry := range map[string]time.Time{
		"expired":     time.Now().Add(-20 * time.Second),
		"zero expiry": {},
	} {
		t.Run(name, func(t *testing.T) {
			fetch := func(context.Context, string) ([]*jwtsvid.SVID, error) {
				return []*jwtsvid.SVID{{ID: id, Expiry: expiry}}, nil
			}
			_, _, err := fetchJWTSVIDFromWorkloadAPI(context.Background(), "conjur", fetch)
			require.NoError(t, err)
		})
	}
}

func TestWorkloadAPITimeoutRejectsNonPositive(t *testing.T) {
	for _, in := range []string{"0", "-5", "-1s", "bogus"} {
		t.Setenv(envConjurSpiffeTimeout, in)
		assert.Equal(t, defaultWorkloadAPITimeout, workloadAPITimeout(), "%s=%q", envConjurSpiffeTimeout, in)
	}
}
