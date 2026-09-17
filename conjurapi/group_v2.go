package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// Group is a v2 group resource. Its shape mirrors Branch (the service returns
// the same Response::ResourceResponse envelope): a name, its parent branch, an
// annotations map, and a server-assigned created_at. A group's only mutable
// state is its annotations.
//
// Note: v2 does not support an owner field (the service rejects it and it is
// absent from the v2 spec), so Group has no Owner — unlike the v1 model.
type Group struct {
	Name        string            `json:"name"`
	Branch      string            `json:"branch"`
	Annotations map[string]string `json:"annotations,omitempty"`
	// CreatedAt is populated on responses; never sent on a request.
	CreatedAt string `json:"created_at,omitempty"`
}

// GroupsResponse is the paginated list envelope returned by the group list
// endpoint.
type GroupsResponse struct {
	Groups []Group `json:"groups"`
	// Count is the grand total of groups matching the query, computed by the
	// server before limit/offset — a reliable pagination termination signal.
	Count int `json:"count"`
}

// HasMore reports whether more groups exist beyond the page returned for filter.
func (r GroupsResponse) HasMore(filter *GroupFilter) bool {
	offset := 0
	if filter != nil {
		offset = filter.Offset
	}
	return offset+len(r.Groups) < r.Count
}

// GroupFilter carries pagination parameters, following the BranchFilter pattern.
type GroupFilter struct {
	Limit  int
	Offset int
}

// GroupMembersResponse is the paginated list of a group's members.
type GroupMembersResponse struct {
	Members []GroupMember `json:"members"`
	// Count is the grand total of members, a reliable termination signal.
	Count int `json:"count"`
}

// HasMore reports whether more members exist beyond the page returned for filter.
func (r GroupMembersResponse) HasMore(filter *GroupFilter) bool {
	offset := 0
	if filter != nil {
		offset = filter.Offset
	}
	return offset+len(r.Members) < r.Count
}

// identifier returns the group's full path identifier (e.g. "data/my-group"),
// the form the single-group routes expect. It joins Branch and Name; if Branch
// is empty, Name is assumed to already be a full identifier.
func (g Group) identifier() string {
	if g.Branch == "" {
		return g.Name
	}
	return g.Branch + "/" + g.Name
}

func (g Group) Validate() error {
	var errs []error
	if g.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required Group attribute Branch"))
	}
	if g.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required Group attribute Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// CreateGroup creates a group and returns it. Only name, branch, and
// annotations are sent — those are the fields the create endpoint permits.
func (c *ClientV2) CreateGroup(group Group) (*Group, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
	}

	req, err := c.CreateGroupRequest(group)
	if err != nil {
		return nil, err
	}

	return c.groupResponse(req)
}

// ReadGroup fetches a single group by its full identifier (e.g. "data/my-group").
func (c *ClientV2) ReadGroup(identifier string) (*Group, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
	}

	req, err := c.ReadGroupRequest(identifier)
	if err != nil {
		return nil, err
	}

	return c.groupResponse(req)
}

// ReadGroups returns a page of groups. filter may be nil for the server default
// page. Use GroupsResponse.HasMore to drive auto-pagination.
func (c *ClientV2) ReadGroups(filter *GroupFilter) (GroupsResponse, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return GroupsResponse{}, fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
	}

	req, err := c.ReadGroupsRequest(filter)
	if err != nil {
		return GroupsResponse{}, err
	}

	groupsResp, err := submitAndUnmarshal[GroupsResponse](c, req)
	if err != nil {
		return GroupsResponse{}, err
	}
	return *groupsResp, nil
}

// UpdateGroup applies a partial (PATCH) update to a group and returns it. The
// group update endpoint permits only annotations, so only the group's
// identifier (Branch/Name) and group.Annotations are used.
func (c *ClientV2) UpdateGroup(group Group) (*Group, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
	}

	req, err := c.UpdateGroupRequest(group.identifier(), group.Annotations)
	if err != nil {
		return nil, err
	}

	return c.groupResponse(req)
}

// DeleteGroup deletes a group. The server responds 204 No Content on success.
func (c *ClientV2) DeleteGroup(identifier string) error {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
	}

	req, err := c.DeleteGroupRequest(identifier)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}

// ListGroupMembers returns a page of a group's members. filter may be nil for
// the server default page. Use GroupMembersResponse.HasMore for auto-pagination.
func (c *ClientV2) ListGroupMembers(groupID string, filter *GroupFilter) (GroupMembersResponse, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return GroupMembersResponse{}, fmt.Errorf(NotSupportedInOldVersions, "Group Membership API", MinVersion)
	}

	req, err := c.ListGroupMembersRequest(groupID, filter)
	if err != nil {
		return GroupMembersResponse{}, err
	}

	membersResp, err := submitAndUnmarshal[GroupMembersResponse](c, req)
	if err != nil {
		return GroupMembersResponse{}, err
	}
	return *membersResp, nil
}

// groupResponse submits req and decodes the single-group JSON body.
func (c *ClientV2) groupResponse(req *http.Request) (*Group, error) {
	return submitAndUnmarshal[Group](c, req)
}

func (c *ClientV2) CreateGroupRequest(group Group) (*http.Request, error) {
	if err := group.Validate(); err != nil {
		return nil, err
	}

	// The create endpoint permits only name, branch, and annotations.
	payload := struct {
		Name        string            `json:"name"`
		Branch      string            `json:"branch"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{
		Name:        group.Name,
		Branch:      group.Branch,
		Annotations: group.Annotations,
	}

	return newV2JSONRequest(http.MethodPost, c.groupsURL(), payload, v2APIHeaderBeta)
}

func (c *ClientV2) ReadGroupRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	groupURL, err := c.groupURL(identifier)
	if err != nil {
		return nil, err
	}

	return newV2Request(http.MethodGet, groupURL, v2APIHeaderBeta)
}

func (c *ClientV2) ReadGroupsRequest(filter *GroupFilter) (*http.Request, error) {
	baseURL := c.groupsURL()
	query := url.Values{}
	if filter != nil {
		if filter.Limit > 0 {
			query.Add("limit", fmt.Sprintf("%d", filter.Limit))
		}
		if filter.Offset > 0 {
			query.Add("offset", fmt.Sprintf("%d", filter.Offset))
		}
	}

	requestURL := baseURL
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", baseURL, encoded)
	}

	return newV2Request(http.MethodGet, requestURL, v2APIHeaderBeta)
}

func (c *ClientV2) UpdateGroupRequest(identifier string, annotations map[string]string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	groupURL, err := c.groupURL(identifier)
	if err != nil {
		return nil, err
	}

	// The group update endpoint permits only annotations, and it MERGES them:
	// keys in the payload are added/overwritten, keys not present are left
	// untouched. Sending an empty map is a no-op server-side, not a "clear all" —
	// this route has no whole-map replacement (verified against the live tenant).
	// Remove a single annotation via DeleteAnnotation instead. `omitempty` keeps
	// a nil map from serialising as `"annotations":null`.
	payload := struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	}{Annotations: annotations}

	return newV2JSONRequest(http.MethodPatch, groupURL, payload, v2APIHeaderBeta)
}

func (c *ClientV2) DeleteGroupRequest(identifier string) (*http.Request, error) {
	if identifier == "" {
		return nil, fmt.Errorf("Must specify an identifier")
	}

	groupURL, err := c.groupURL(identifier)
	if err != nil {
		return nil, err
	}

	return newV2Request(http.MethodDelete, groupURL, v2APIHeaderBeta)
}

func (c *ClientV2) ListGroupMembersRequest(groupID string, filter *GroupFilter) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}

	baseURL, err := c.groupMembersURL(groupID)
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

	requestURL := baseURL
	if encoded := query.Encode(); encoded != "" {
		requestURL = fmt.Sprintf("%s?%s", baseURL, encoded)
	}

	return newV2Request(http.MethodGet, requestURL, v2APIHeaderBeta)
}

// escapeGroupIdentifier percent-escapes each slash-separated segment of a
// resource identifier while preserving the slashes themselves, so an identifier
// like "data/test/my host" becomes "data/test/my%20host". Group v2 routes take
// a "*glob" trailing parameter (group identifiers, member ids) that captures
// slashes, so the path structure is kept while URL-significant characters in
// each segment are made safe.
//
// Empty, "." and ".." segments are rejected rather than escaped: makeRouterURL
// joins with path.Join, which resolves "." / ".." (so "data/../admin" would
// collapse to "admin" and address a different resource — a path-traversal). It
// delegates to escapePathSegments for that guard.
func escapeGroupIdentifier(what, identifier string) (string, error) {
	segments, err := escapePathSegments(what, strings.Split(identifier, "/"))
	if err != nil {
		return "", err
	}
	return strings.Join(segments, "/"), nil
}

// groupPathURL builds a groups URL, inserting the account segment per the
// SaaS/Self-Hosted convention (omitted on SaaS) and appending the given
// trailing segments. Centralizing the branching keeps groupsURL, groupURL, and
// groupMembersURL from drifting as routes are added.
func (c *ClientV2) groupPathURL(segments ...string) string {
	components := []string{"groups"}
	if account := c.config.Account; account != "" && !c.config.IsSaaS() {
		components = append(components, account)
	}
	components = append(components, segments...)
	return makeRouterURL(c.config.ApplianceURL, components...).String()
}

// groupsURL builds the collection URL: /groups(/{account})
func (c *ClientV2) groupsURL() string {
	return c.groupPathURL()
}

// groupURL builds the single-group URL: /groups(/{account})/{identifier}. The
// identifier maps to the route's *identifier glob: slashes are meaningful path
// separators (preserved), other characters are percent-escaped.
func (c *ClientV2) groupURL(identifier string) (string, error) {
	escaped, err := escapeGroupIdentifier("Group identifier", identifier)
	if err != nil {
		return "", err
	}
	return c.groupPathURL(escaped), nil
}

// groupMembersURL builds the members sub-resource URL:
// /groups(/{account})/{identifier}/members
func (c *ClientV2) groupMembersURL(groupID string) (string, error) {
	escaped, err := escapeGroupIdentifier("Group identifier", groupID)
	if err != nil {
		return "", err
	}
	return c.groupPathURL(escaped, "members"), nil
}
