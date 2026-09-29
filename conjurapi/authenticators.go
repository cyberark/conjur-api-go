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

// Bool is a helper function to create a pointer to a boolean value.
func Bool(v bool) *bool { return &v }

type AuthenticatorBase struct {
	Type        string                 `json:"type"`
	Subtype     *string                `json:"subtype,omitempty"`
	Name        string                 `json:"name"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Owner       *AuthOwner             `json:"owner,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
}

type AuthenticatorResponse struct {
	AuthenticatorBase
	Branch string `json:"branch"`
}

type AuthOwner struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type AuthenticatorListResponse struct {
	Authenticators []AuthenticatorResponse `json:"authenticators"`
	Count          int                     `json:"count"`
}

const AuthenticatorsMinVersion = MinVersion

// CreateAuthenticator creates a new authenticator instance using the V2 API.
//
// The authenticated user must have create privileges on the conjur/authn-<type> policy.
func (c *ClientV2) CreateAuthenticator(authenticator *AuthenticatorBase) (*AuthenticatorResponse, error) {
	req, err := c.CreateAuthenticatorRequest(authenticator)
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := AuthenticatorResponse{}
	return &obj, response.JSONResponse(res, &obj)
}

// GetAuthenticator gets an existing authenticator instance using the V2 API.
//
// The authenticated user must have read privileges on the authenticator.
func (c *ClientV2) GetAuthenticator(authenticatorType string, authenticatorName string) (*AuthenticatorResponse, error) {
	req, err := c.GetAuthenticatorRequest(authenticatorType, authenticatorName)
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := AuthenticatorResponse{}
	return &obj, response.JSONResponse(res, &obj)
}

// UpdateAuthenticator updates an existing authenticator instance using the V2 API.
// It currently only supports enabling/disabling an authenticator.
//
// The authenticated user must have update privileges on the authenticator.
func (c *ClientV2) UpdateAuthenticator(authenticatorType string, authenticatorName string, enabled bool) (*AuthenticatorResponse, error) {
	req, err := c.UpdateAuthenticatorRequest(authenticatorType, authenticatorName, enabled)
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := AuthenticatorResponse{}
	return &obj, response.JSONResponse(res, &obj)
}

// DeleteAuthenticator deletes an existing authenticator instance using the V2 API.
//
// The authenticated user must have update privileges on the authenticator.
func (c *ClientV2) DeleteAuthenticator(authenticatorType string, authenticatorName string) error {
	req, err := c.DeleteAuthenticatorRequest(authenticatorType, authenticatorName)
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

// ListAuthenticators gets a list of existing authenticators using the V2 API.
//
// The authenticated user must have read privileges on the authenticators.
func (c *ClientV2) ListAuthenticators() (*AuthenticatorListResponse, error) {
	req, err := c.ListAuthenticatorsRequest()
	if err != nil {
		return nil, err
	}

	res, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	obj := AuthenticatorListResponse{}
	return &obj, response.JSONResponse(res, &obj)
}
