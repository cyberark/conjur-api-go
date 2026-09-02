package conjurapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	internalswa "github.com/cyberark/conjur-api-go/internal/swa-sdk-go"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
	"github.com/cyberark/conjur-api-go/conjurapi/swa"
)

// SWA returns a client for managing Secure Workload Access (SWA) resources
// (Trust Domains, Server Groups, Node Groups, Servers, and well-known
// discovery endpoints). SWA is only supported on Conjur Cloud / SaaS
// environments.
func (c *ClientV2) SWA() (swa.Client, error) {
	if !c.config.IsSaaS() {
		return nil, fmt.Errorf(NotSupportedInConjurEnterprise, "SWA API")
	}

	opts := []internalswa.Option{
		internalswa.WithBaseURL(c.config.ApplianceURL),
		// Inject Conjur's own configured *http.Client (TLS trust store, proxy,
		// HTTPTimeout) rather than letting the SDK build a fresh one with its
		// own 30s default timeout: a WithRoundTripper-only setup would leave
		// that default-timeout client wrapping every call, silently
		// truncating requests at 30s even when HTTPTimeout is configured
		// higher.
		internalswa.WithHTTPClient(c.httpClient),
		// TokenSource is the SDK's purpose-built extension point for supplying
		// an access token: the SDK's own auth editor consults it per request
		// (so refresh is transparent) and writes the Authorization header
		// itself, using the same `Token token="..."` scheme
		// createAuthRequest uses. Preferred over a request editor writing the
		// header directly, since that's exactly what this option exists for.
		internalswa.WithTokenSource(internalswa.TokenSourceFunc(func(context.Context) (string, error) {
			if err := c.RefreshToken(); err != nil {
				return "", err
			}
			return c.authToken.Base64(), nil
		})),
		// Telemetry isn't an auth concern, so it stays a plain request editor.
		internalswa.WithRequestEditors(func(_ context.Context, req *http.Request) error {
			req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
			return nil
		}),
	}

	// Mirror the CONJURAPI_LOG-driven debug level the rest of the client
	// honors (see conjurapi/logging): when enabled, SWA requests/responses
	// (with sensitive headers redacted) are logged to the same destination,
	// using the SDK's own WithDebug rather than a bespoke dump mechanism.
	if logging.ApiLog.Level == logrus.DebugLevel {
		opts = append(opts, internalswa.WithDebug(logging.ApiLog.Out))
	}

	return internalswa.NewClient(opts...)
}
