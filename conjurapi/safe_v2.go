package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Safe is a v2 safe, a policy branch at data/<type>/<name> with safe-specific
// fields. A managed safe's branch is data/vault/<name>.
type Safe struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Environment string            `json:"environment,omitempty"`
	Description string            `json:"description,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	// Set by the server.
	CreatedAt    string `json:"created_at,omitempty"`
	SecretsCount *int   `json:"secrets_count,omitempty"`
	Replicated   *bool  `json:"replicated,omitempty"`
}

// SafesResponse is the paginated list envelope.
type SafesResponse struct {
	Safes []Safe `json:"safes"`
	// Count is the grand total, not the page size.
	Count int `json:"count"`
}

// SafeFilter carries pagination and filters for ListSafes.
type SafeFilter struct {
	Limit  int
	Offset int
	// SafeType lists only safes of this type, for example managed. The server
	// checks the value.
	SafeType string
	// Extended asks the server to populate SecretsCount.
	Extended bool
}

const safeExtendedProjection = "extended"

// CreateSafe creates a safe and returns it.
func (c *ClientV2) CreateSafe(safe Safe) (*Safe, error) {
	if err := safe.Validate(); err != nil {
		return nil, err
	}

	req, err := c.CreateSafeRequest(safe)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Safe](c, req)
}

// GetSafe fetches a single safe by type and name.
func (c *ClientV2) GetSafe(safeType, name string) (*Safe, error) {
	return c.getSafe(safeType, name, false)
}

// GetSafeExtended fetches a safe with SecretsCount populated.
func (c *ClientV2) GetSafeExtended(safeType, name string) (*Safe, error) {
	return c.getSafe(safeType, name, true)
}

// ListSafes returns a page of safes; filter may be nil.
func (c *ClientV2) ListSafes(filter *SafeFilter) (*SafesResponse, error) {
	req, err := c.ListSafesRequest(filter)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[SafesResponse](c, req)
}

// UpdateSafe applies a partial (PATCH) update to a safe's environment,
// description and annotations and returns it. Fields left empty keep their
// stored values, and annotations are merged into the stored ones. To clear a
// field or remove an annotation, use ReplaceSafe.
func (c *ClientV2) UpdateSafe(safe Safe) (*Safe, error) {
	if err := safe.Validate(); err != nil {
		return nil, err
	}

	req, err := c.UpdateSafeRequest(safe)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Safe](c, req)
}

// ReplaceSafe replaces a safe's environment, description and annotations and
// returns it. Fields left empty are cleared, not kept; to change only some
// fields, use UpdateSafe.
func (c *ClientV2) ReplaceSafe(safe Safe) (*Safe, error) {
	if err := safe.Validate(); err != nil {
		return nil, err
	}

	req, err := c.ReplaceSafeRequest(safe)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Safe](c, req)
}

// DeleteSafe deletes a safe with all its secrets and sub-branches. The server
// doesn't check that the safe is empty; read SecretsCount with GetSafeExtended
// first. Safes nested under its name, such as <name>/sub, are separate safes
// and are kept.
func (c *ClientV2) DeleteSafe(safeType, name string) error {
	req, err := c.DeleteSafeRequest(safeType, name)
	if err != nil {
		return err
	}

	return submitAndEmpty(c, req)
}

func (c *ClientV2) CreateSafeRequest(safe Safe) (*http.Request, error) {
	// Server-set fields must not be in the body.
	payload, err := json.Marshal(struct {
		Type        string            `json:"type"`
		Name        string            `json:"name"`
		Environment string            `json:"environment,omitempty"`
		Description string            `json:"description,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Type:        safe.Type,
		Name:        safe.Name,
		Environment: safe.Environment,
		Description: safe.Description,
		Annotations: safe.Annotations,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.safesURL(), bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) GetSafeRequest(safeType, name string, extended bool) (*http.Request, error) {
	if err := validateSafeTypeName(safeType, name); err != nil {
		return nil, err
	}

	requestURL, err := c.safeURL(safeType, name)
	if err != nil {
		return nil, err
	}
	if extended {
		requestURL = fmt.Sprintf("%s?projection=%s", requestURL, safeExtendedProjection)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) ListSafesRequest(filter *SafeFilter) (*http.Request, error) {
	baseURL := c.safesURL()
	query := url.Values{}
	if filter != nil {
		if filter.Limit > 0 {
			query.Add("limit", fmt.Sprintf("%d", filter.Limit))
		}
		if filter.Offset > 0 {
			query.Add("offset", fmt.Sprintf("%d", filter.Offset))
		}
		if filter.SafeType != "" {
			if strings.ContainsAny(filter.SafeType, " \t\r\n") {
				return nil, fmt.Errorf("safe type %q must not contain whitespace", filter.SafeType)
			}
			query.Add("filter", "safe_type eq "+filter.SafeType)
		}
		if filter.Extended {
			query.Add("projection", safeExtendedProjection)
		}
	}

	requestURL := baseURL
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", baseURL, encoded)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) UpdateSafeRequest(safe Safe) (*http.Request, error) {
	return c.safeFieldsRequest(http.MethodPatch, safe)
}

func (c *ClientV2) ReplaceSafeRequest(safe Safe) (*http.Request, error) {
	return c.safeFieldsRequest(http.MethodPut, safe)
}

func (c *ClientV2) DeleteSafeRequest(safeType, name string) (*http.Request, error) {
	if err := validateSafeTypeName(safeType, name); err != nil {
		return nil, err
	}

	safeURL, err := c.safeURL(safeType, name)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodDelete, safeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (s Safe) Validate() error {
	var errs []error
	// The server validates the type value.
	if s.Type == "" {
		errs = append(errs, fmt.Errorf("Missing required Safe attribute Type"))
	}
	if s.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required Safe attribute Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func validateSafeTypeName(safeType, name string) error {
	var errs []error
	if safeType == "" {
		errs = append(errs, fmt.Errorf("Must specify a Safe type"))
	}
	if name == "" {
		errs = append(errs, fmt.Errorf("Must specify a Safe name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *ClientV2) getSafe(safeType, name string, extended bool) (*Safe, error) {
	req, err := c.GetSafeRequest(safeType, name, extended)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Safe](c, req)
}

// safeFieldsRequest builds the update (PATCH) and replace (PUT) requests,
// which send the same body.
func (c *ClientV2) safeFieldsRequest(method string, safe Safe) (*http.Request, error) {
	if err := validateSafeTypeName(safe.Type, safe.Name); err != nil {
		return nil, err
	}

	// name and type come from the URL path and must not be in the body.
	// omitempty leaves empty fields out of the body, which is what lets a
	// PATCH keep them.
	payload, err := json.Marshal(struct {
		Environment string            `json:"environment,omitempty"`
		Description string            `json:"description,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Environment: safe.Environment,
		Description: safe.Description,
		Annotations: safe.Annotations,
	})
	if err != nil {
		return nil, err
	}

	safeURL, err := c.safeURL(safe.Type, safe.Name)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, safeURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) safesURL() string {
	return makeRouterURL(c.config.ApplianceURL, "safes").String()
}

// escapeSafeIdentifier escapes a slash-separated identifier as one path
// segment, so each "/" is sent as %2F. With literal slashes, the server would
// take a name such as A/permissions/group/g for a sub-route of safe A. Empty,
// "." and ".." parts are rejected.
func escapeSafeIdentifier(what, identifier string) (string, error) {
	if _, err := escapePathSegments(what, strings.Split(identifier, "/")); err != nil {
		return "", err
	}
	return url.PathEscape(identifier), nil
}

func (c *ClientV2) safeURL(safeType, name string) (string, error) {
	escapedType, err := escapePathSegments("Safe type", []string{safeType})
	if err != nil {
		return "", err
	}
	escapedName, err := escapeSafeIdentifier("Safe name", name)
	if err != nil {
		return "", err
	}
	return makeRouterURL(c.config.ApplianceURL, "safes", escapedType[0], escapedName).String(), nil
}
