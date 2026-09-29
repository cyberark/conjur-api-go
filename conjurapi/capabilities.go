package conjurapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
)

// checkCapability enforces cap for this client. See contract.CheckCapability.
func (c *Client) checkCapability(cap contract.Capability) error {
	return contract.CheckCapability(cap, c.config.IsSaaS(), c.backendVersion)
}

// CapabilityStatus reports cap's availability for this client. See contract.Status.
func (c *Client) CapabilityStatus(cap contract.Capability) contract.CapabilityStatus {
	return contract.Status(cap, c.config.IsSaaS(), c.backendVersion)
}

// checkRequestCapability enforces the Capability, if any, of req's route.
// Requests outside the API base URL aren't API routes, so aren't gated.
func (c *Client) checkRequestCapability(req *http.Request) error {
	baseURL := normalizeBaseURL(c.config.ApplianceURL)
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	route, ok := strings.CutPrefix(req.URL.EscapedPath(), strings.TrimSuffix(base.EscapedPath(), "/"))
	if !ok || (route != "" && !strings.HasPrefix(route, "/")) {
		return nil
	}

	if cap, ok := contract.RouteCapability(req.Method, route, req.URL.Query()); ok {
		return c.checkCapability(cap)
	}
	return nil
}
