package conjurapi

import (
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// AuthenticatorStatusResponse contains information about
// the status of an authenticator.
type AuthenticatorStatusResponse struct {
	// Status of the policy validation.
	Status string `json:"status"`
	Error  string `json:"error"`
}

// AuthenticatorStatus queries the policy-validation status of an authenticator
// service.
//
// On failure the server returns a non-2xx response and this method returns a
// *[response.ConjurError]. Inspect [response.ConjurError.Code] via [errors.As]
// to distinguish error conditions:
//
//	_, err := client.AuthenticatorStatus("authn-jwt", "my-service")
//	var conjurErr *response.ConjurError
//	if errors.As(err, &conjurErr) {
//	    // Conjur Enterprise: HTTP 404 = authenticator type not supported or
//	    //   webservice not defined in policy; HTTP 500 = authenticator is
//	    //   defined but not enabled (AuthenticatorNotWhitelisted).
//	    // SaaS: both conditions map to HTTP 500.
//	    fmt.Println("HTTP status:", conjurErr.Code)
//	}
func (c *Client) AuthenticatorStatus(authenticatorType string, serviceID string) (*AuthenticatorStatusResponse, error) {
	req, err := c.AuthenticatorStatusRequest(authenticatorType, serviceID)
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := AuthenticatorStatusResponse{}
	return &obj, response.JSONResponse(res, &obj)
}

// EnableAuthenticator enables or disables an authenticator instance
//
// The authenticated user must be admin
func (c *Client) EnableAuthenticator(authenticatorType string, serviceID string, enabled bool) error {
	req, err := c.EnableAuthenticatorRequest(authenticatorType, serviceID, enabled)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	err = response.EmptyResponse(resp)
	if err != nil {
		return err
	}

	return nil
}

// SetAuthenticatorEnabled enables or disables the authenticator with the
// combined "authn-<type>/<name>" id. Config.Environment picks the API, V2 on
// SaaS and v1 on Self-Hosted; it isn't checked against the server. With a SaaS
// Environment, a Self-Hosted server answers this and the ClientV2
// authenticator calls with a 404. With a Self-Hosted Environment, SaaS still
// serves this call over v1, but the ClientV2 calls fail the version check.
func (c *Client) SetAuthenticatorEnabled(id string, enabled bool) error {
	authenticatorType, name, err := ParseAuthenticatorID(id)
	if err != nil {
		return err
	}

	if c.config.IsSaaS() {
		_, err := c.V2().SetAuthenticatorEnabledV2(authenticatorType, name, enabled)
		return err
	}

	return c.EnableAuthenticator(v1AuthenticatorType(authenticatorType), name, enabled)
}

// v1AuthenticatorType maps a V2 type back to the v1 short form ("iam", "cert").
func v1AuthenticatorType(v2AuthenticatorType string) string {
	switch v2AuthenticatorType {
	case "aws_iam":
		return "iam"
	case "certificate":
		return "cert"
	default:
		return v2AuthenticatorType
	}
}
