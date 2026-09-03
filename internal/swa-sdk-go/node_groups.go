package swa

import (
	"context"
	"iter"
	"net/http"
	"strings"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// NodeGroupsService provides access to the SWA node-group resource. Node groups
// are scoped to a server group within a trust domain.
type NodeGroupsService struct {
	client *Client
}

// Get returns the named node group.
func (s *NodeGroupsService) Get(ctx context.Context, trustDomain, serverGroup, name string) (*NodeGroup, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetNodeGroup(ctx, trustDomain, serverGroup, name, &swaapi.GetNodeGroupParams{Accept: acceptV2})
	})
	if err != nil {
		return nil, err
	}
	var out NodeGroup
	if err := HandleResponse(swaerrors.OpNodeGroupsGet, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns a single page of node groups within a server group.
func (s *NodeGroupsService) List(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) (*NodeGroupList, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetNodeGroups(ctx, trustDomain, serverGroup, &swaapi.GetNodeGroupsParams{
			Limit:  opts.limit(),
			Offset: opts.offset(),
			Accept: acceptV2,
		})
	})
	if err != nil {
		return nil, err
	}
	var out NodeGroupList
	if err := HandleResponse(swaerrors.OpNodeGroupsList, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// All returns an iterator that transparently paginates over every node group in
// a server group.
func (s *NodeGroupsService) All(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) iter.Seq2[NodeGroup, error] {
	var pageSize int32
	if opts != nil {
		pageSize = opts.Limit
	}
	return paginate(ctx, pageSize, func(ctx context.Context, limit, offset int32) ([]NodeGroup, error) {
		page, err := s.List(ctx, trustDomain, serverGroup, &ListOptions{Limit: limit, Offset: offset})
		if err != nil {
			return nil, err
		}
		return page.NodeGroups, nil
	})
}

// Create creates a node group in the server group. The request is validated
// client-side before it is sent; an invalid request yields a *swaerrors.ValidationError.
func (s *NodeGroupsService) Create(ctx context.Context, trustDomain, serverGroup string, req NodeGroupCreateRequest) (*NodeGroup, error) {
	if err := ValidateNodeGroupCreateRequest(req); err != nil {
		return nil, err
	}
	resp, err := s.client.Execute(ctx, false, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PostNodeGroups(ctx, trustDomain, serverGroup, &swaapi.PostNodeGroupsParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out NodeGroup
	if err := HandleResponse(swaerrors.OpNodeGroupsCreate, resp, &out, []int{http.StatusCreated, http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update patches a node group's description and workload configuration.
func (s *NodeGroupsService) Update(ctx context.Context, trustDomain, serverGroup, name string, req NodeGroupUpdateRequest) (*NodeGroup, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PatchNodeGroup(ctx, trustDomain, serverGroup, name, &swaapi.PatchNodeGroupParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out NodeGroup
	if err := HandleResponse(swaerrors.OpNodeGroupsUpdate, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes a node group.
func (s *NodeGroupsService) Delete(ctx context.Context, trustDomain, serverGroup, name string) error {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.DeleteNodeGroup(ctx, trustDomain, serverGroup, name, &swaapi.DeleteNodeGroupParams{Accept: acceptV2})
	})
	if err != nil {
		return err
	}
	return HandleResponse(swaerrors.OpNodeGroupsDelete, resp, nil, []int{http.StatusNoContent, http.StatusOK})
}

// Apply ensures a node group matching req exists within the server group,
// creating it when absent and updating it to match when present. When req omits
// the workload configuration, an existing node group is reset to its
// workload-type defaults (see ResetWorkloadConfiguration) rather than left
// untouched — the declarative contract is that req is the complete desired state.
// See the reconcile notes in apply.go.
func (s *NodeGroupsService) Apply(ctx context.Context, trustDomain, serverGroup string, req NodeGroupCreateRequest) (*NodeGroup, ApplyAction, error) {
	if err := ValidateNodeGroupCreateRequest(req); err != nil {
		return nil, "", err
	}
	_, err := s.Get(ctx, trustDomain, serverGroup, req.Name)
	switch {
	case err == nil:
		ng, uErr := s.Update(ctx, trustDomain, serverGroup, req.Name, toUpdateNodeGroupRequest(req))
		if uErr != nil {
			return nil, "", uErr
		}
		return ng, ApplyActionUpdated, nil
	case swaerrors.IsNotFound(err):
		ng, cErr := s.Create(ctx, trustDomain, serverGroup, req)
		if cErr != nil {
			return nil, "", cErr
		}
		return ng, ApplyActionCreated, nil
	default:
		return nil, "", err
	}
}

// toUpdateNodeGroupRequest projects a create request onto the node-group update
// request. The name and workload type are immutable and therefore not carried
// over. A nil workload configuration is mapped to an explicit reset so that
// Apply's declarative contract holds (req is the complete desired state).
func toUpdateNodeGroupRequest(req NodeGroupCreateRequest) NodeGroupUpdateRequest {
	wc := req.WorkloadConfiguration
	if wc == nil {
		wc = ResetWorkloadConfiguration()
	}
	return NodeGroupUpdateRequest{
		Description:           req.Description,
		WorkloadConfiguration: wc,
	}
}

// ValidateNodeGroupCreateRequest checks a node-group create request: a valid name
// and a non-empty workload type.
func ValidateNodeGroupCreateRequest(req NodeGroupCreateRequest) error {
	var v []swaerrors.FieldViolation
	resourceNameRule.validate("name", req.Name, &v)
	if strings.TrimSpace(string(req.WorkloadType)) == "" {
		v = append(v, swaerrors.FieldViolation{
			Field:   "workload_type",
			Message: "must be set (e.g. \"unix\" or \"kubernetes\")",
		})
	}
	return swaerrors.NewValidationError(swaerrors.OpNodeGroupsCreate, v)
}

// ResetWorkloadConfiguration returns a WorkloadConfiguration that instructs the
// control plane to reset a node group's workload configuration back to the
// defaults derived from its workload type.
//
// The API treats a *present but empty* WorkloadConfiguration (the object is sent,
// but every field is unset) as "reset everything to defaults", as distinct from
// omitting the object entirely (which leaves the existing configuration
// untouched). That distinction is easy to get wrong — sending nil where a reset
// was intended leaves stale data on the backend — so this constructor names the
// intent explicitly.
func ResetWorkloadConfiguration() *WorkloadConfiguration {
	return &WorkloadConfiguration{}
}
