package conjurapi

import (
	"errors"
	"net/http"
)

// contractVersionHeader carries the server version the client assumes; older servers ignore it.
const contractVersionHeader = "Contract-Version"

// retryAfterVersionMismatch resends req once against the current version.
// If req can't be resent or the version can't be retrieved, it returns resp.
func (c *Client) retryAfterVersionMismatch(req *http.Request, resp *http.Response, stale, hinted string) (*http.Response, error) {
	c.version.forgetConfirmed(stale, hinted)
	if hinted != "" {
		// forgetConfirmed cached hinted directly; get() below won't call
		// fetchAndPersistServerVersion to learn it, so persist it here instead.
		c.version.persist(hinted)
	}
	retry, err := cloneRequestForRetry(req)
	if err != nil {
		return resp, nil
	}
	if _, err := c.version.get(c.fetchAndPersistServerVersion); err != nil {
		return resp, nil
	}
	resp.Body.Close()

	// The current version may not support what req needs.
	if err := c.checkRequestCapability(retry); err != nil {
		return nil, err
	}
	if err := c.createAuthRequest(retry); err != nil {
		return nil, err
	}
	c.version.pin(retry)
	return c.submitRequestWithCustomAuth(retry)
}

// isVersionMismatch reports whether resp is a stale Contract-Version
// refusal, and the server's current version if resp named one directly
// (sparing a separate lookup). Nothing else in Conjur's API returns 426, so
// the status code alone is unambiguous - no body to read or parse.
func isVersionMismatch(resp *http.Response) (mismatch bool, hinted string) {
	if resp.StatusCode != http.StatusUpgradeRequired {
		return false, ""
	}
	return true, resp.Header.Get("Upgrade")
}

// cloneRequestForRetry copies req with a fresh body from GetBody, which
// http.NewRequest sets only for in-memory bodies.
func cloneRequestForRetry(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("request body can't be sent again")
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}
