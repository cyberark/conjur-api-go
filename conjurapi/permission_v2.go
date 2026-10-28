package conjurapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
)

// PermissionKind is the kind of resource a permission is granted on.
type PermissionKind string

// PermissionTarget identifies the resource a permission applies to.
type PermissionTarget struct {
	Kind       PermissionKind
	Identifier string
}

// PermissionGrant is the subject and privileges of a grant.
type PermissionGrant struct {
	Subject    Subject
	Privileges []string
}

// PermissionFilter carries pagination parameters for ListPermissions.
type PermissionFilter struct {
	Limit  int
	Offset int
}

// grantBody is the wire shape the service expects for create/update.
type grantBody struct {
	Subject    Subject  `json:"subject"`
	Privileges []string `json:"privileges"`
}

const (
	PermissionKindWorkload PermissionKind = "workload"
	PermissionKindGroup    PermissionKind = "group"
	PermissionKindBranch   PermissionKind = "branch"
	// PermissionKindSafe targets a safe. Its identifier is "<type>/<name>",
	// for example "managed/MySafe". The name may contain "/".
	PermissionKindSafe PermissionKind = "safe"
)

// permissionKindRoutes maps each kind to the collection its permission routes
// hang off.
var permissionKindRoutes = map[PermissionKind]string{
	PermissionKindWorkload: "workloads",
	PermissionKindGroup:    "groups",
	PermissionKindBranch:   "branches",
	PermissionKindSafe:     "safes",
}

// SupportedPermissionKinds returns the resource kinds the SDK can manage
// permissions on, sorted for stable output.
func SupportedPermissionKinds() []PermissionKind {
	kinds := make([]PermissionKind, 0, len(permissionKindRoutes))
	for k := range permissionKindRoutes {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

// SupportedPermissionKindNames returns SupportedPermissionKinds as strings, for
// callers that display the kinds.
func SupportedPermissionKindNames() []string {
	kinds := SupportedPermissionKinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return names
}

// GrantPermission grants a subject privileges on a resource. A subject that
// already has a grant gets HTTP 409; use UpdatePermission for it.
func (c *ClientV2) GrantPermission(target PermissionTarget, grant PermissionGrant) (*Permission, error) {
	if err := c.checkCapability(contract.CapabilityPermissionsV2); err != nil {
		return nil, err
	}
	if err := validateGrant(target, grant); err != nil {
		return nil, err
	}

	req, err := c.GrantPermissionRequest(target, grant)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Permission](c, req)
}

// UpdatePermission sets a subject's privileges on a resource, replacing any it
// had. The service creates the grant when the subject has none. Groups have no
// update route; revoke and re-grant instead.
func (c *ClientV2) UpdatePermission(target PermissionTarget, grant PermissionGrant) (*Permission, error) {
	if err := c.checkCapability(contract.CapabilityPermissionsV2); err != nil {
		return nil, err
	}
	if err := validateGrant(target, grant); err != nil {
		return nil, err
	}

	req, err := c.UpdatePermissionRequest(target, grant)
	if err != nil {
		return nil, err
	}
	return submitAndUnmarshal[Permission](c, req)
}

// RevokePermission removes a subject's permissions on a resource.
func (c *ClientV2) RevokePermission(target PermissionTarget, subject Subject) error {
	if err := c.checkCapability(contract.CapabilityPermissionsV2); err != nil {
		return err
	}
	if target.Identifier == "" || subject.Id == "" || subject.Kind == "" {
		return fmt.Errorf("Must specify a resource identifier and a subject id and kind")
	}

	req, err := c.RevokePermissionRequest(target, subject)
	if err != nil {
		return err
	}
	return submitAndEmpty(c, req)
}

// ListPermissions returns a page of the permitted roles on a resource.
func (c *ClientV2) ListPermissions(target PermissionTarget, filter *PermissionFilter) (*PermissionResponse, error) {
	if err := c.checkCapability(contract.CapabilityPermissionsV2); err != nil {
		return nil, err
	}
	if target.Identifier == "" {
		return nil, fmt.Errorf("Must specify a resource identifier")
	}

	req, err := c.ListPermissionsRequest(target, filter)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[PermissionResponse](c, req)
}

func (c *ClientV2) GrantPermissionRequest(target PermissionTarget, grant PermissionGrant) (*http.Request, error) {
	base, err := c.permissionsBaseURL(target)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(grantBody{Subject: grant.Subject, Privileges: grant.Privileges})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, base, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) UpdatePermissionRequest(target PermissionTarget, grant PermissionGrant) (*http.Request, error) {
	roleURL, err := c.permissionsRoleURL(target, grant.Subject)
	if err != nil {
		return nil, err
	}
	if target.Kind == PermissionKindGroup {
		return nil, fmt.Errorf("updating privileges in place is not supported for %s; revoke and re-grant instead", target.Kind)
	}

	// Only the privileges of an existing grant are sent. Safes take PATCH on
	// this route; a PUT on a safe's permissions replaces the whole list.
	method := http.MethodPut
	if target.Kind == PermissionKindSafe {
		method = http.MethodPatch
	}
	payload, err := json.Marshal(struct {
		Privileges []string `json:"privileges"`
	}{Privileges: grant.Privileges})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, roleURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) RevokePermissionRequest(target PermissionTarget, subject Subject) (*http.Request, error) {
	roleURL, err := c.permissionsRoleURL(target, subject)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodDelete, roleURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

func (c *ClientV2) ListPermissionsRequest(target PermissionTarget, filter *PermissionFilter) (*http.Request, error) {
	base, err := c.permissionsBaseURL(target)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	if filter != nil {
		if filter.Limit > 0 {
			query.Add("limit", fmt.Sprintf("%d", filter.Limit))
		}
		if filter.Offset > 0 {
			query.Add("offset", fmt.Sprintf("%d", filter.Offset))
		}
	}
	requestURL := base
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", base, encoded)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

// validateGrant checks that the grant carries what the request needs. The
// privileges and the grantee kind are validated by the service.
func validateGrant(target PermissionTarget, grant PermissionGrant) error {
	var errs []error
	if target.Identifier == "" {
		errs = append(errs, fmt.Errorf("Must specify a resource identifier"))
	}
	if grant.Subject.Id == "" || grant.Subject.Kind == "" {
		errs = append(errs, fmt.Errorf("Must specify a subject id and kind"))
	}
	if len(grant.Privileges) == 0 {
		errs = append(errs, fmt.Errorf("Must specify at least one privilege"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// permissionsBaseURL builds /{collection}/{identifier}/permissions. It checks
// the capability too, because SubmitRequest lets branch routes through on
// Self-Hosted.
func (c *ClientV2) permissionsBaseURL(target PermissionTarget) (string, error) {
	if err := c.checkCapability(contract.CapabilityPermissionsV2); err != nil {
		return "", err
	}
	components, err := c.permissionResourceComponents(target)
	if err != nil {
		return "", err
	}
	components = append(components, "permissions")
	return makeRouterURL(c.config.ApplianceURL, components...).String(), nil
}

// escapePermissionIdentifier escapes each segment of a slash-separated
// identifier, rejecting empty, "." and ".." ones.
func escapePermissionIdentifier(what, identifier string) (string, error) {
	segments, err := escapePathSegments(what, strings.Split(identifier, "/"))
	if err != nil {
		return "", err
	}
	return strings.Join(segments, "/"), nil
}

// permissionsRoleURL appends /{role_kind}/{role_id} to the permissions URL.
func (c *ClientV2) permissionsRoleURL(target PermissionTarget, subject Subject) (string, error) {
	base, err := c.permissionsBaseURL(target)
	if err != nil {
		return "", err
	}
	escapedKind, err := escapePathSegments("Role kind", []string{subject.Kind})
	if err != nil {
		return "", err
	}
	escapedRole, err := escapePermissionIdentifier("Role id", subject.Id)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{base, escapedKind[0], escapedRole}, "/"), nil
}

// permissionResourceComponents returns the path components addressing the target.
func (c *ClientV2) permissionResourceComponents(target PermissionTarget) ([]string, error) {
	if target.Identifier == "" {
		return nil, fmt.Errorf("Must specify a resource identifier")
	}

	escapedID, err := escapePermissionIdentifier("Resource identifier", target.Identifier)
	if err != nil {
		return nil, err
	}

	route, ok := permissionKindRoutes[target.Kind]
	if !ok {
		return nil, fmt.Errorf("unsupported permission kind %q (supported: %s)", target.Kind, strings.Join(SupportedPermissionKindNames(), ", "))
	}
	if target.Kind == PermissionKindSafe && !strings.Contains(target.Identifier, "/") {
		return nil, fmt.Errorf("a safe identifier is <type>/<name>, got %q", target.Identifier)
	}
	return []string{route, escapedID}, nil
}
