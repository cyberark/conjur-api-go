package swa

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"strings"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/internal/gen/swa"
)

// ServersService provides access to the SWA server (component) resource. Servers
// are scoped to a server group within a trust domain.
type ServersService struct {
	client *Client
}

// Get returns the named server.
func (s *ServersService) Get(ctx context.Context, trustDomain, serverGroup, name string) (*Server, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetServer(ctx, trustDomain, serverGroup, name, &swaapi.GetServerParams{Accept: acceptV2})
	})
	if err != nil {
		return nil, err
	}
	var out Server
	if err := HandleResponse(swaerrors.OpServersGet, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns a single page of servers within a server group.
func (s *ServersService) List(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) (*ServerList, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.GetServers(ctx, trustDomain, serverGroup, &swaapi.GetServersParams{
			Limit:  opts.limit(),
			Offset: opts.offset(),
			Accept: acceptV2,
		})
	})
	if err != nil {
		return nil, err
	}
	var out ServerList
	if err := HandleResponse(swaerrors.OpServersList, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// All returns an iterator that transparently paginates over every server in a
// server group.
func (s *ServersService) All(ctx context.Context, trustDomain, serverGroup string, opts *ListOptions) iter.Seq2[Server, error] {
	var pageSize int32
	if opts != nil {
		pageSize = opts.Limit
	}
	return paginate(ctx, pageSize, func(ctx context.Context, limit, offset int32) ([]Server, error) {
		page, err := s.List(ctx, trustDomain, serverGroup, &ListOptions{Limit: limit, Offset: offset})
		if err != nil {
			return nil, err
		}
		return page.Components, nil
	})
}

// Create registers a server in the server group. The request is validated
// client-side before it is sent; an invalid request yields a *swaerrors.ValidationError.
func (s *ServersService) Create(ctx context.Context, trustDomain, serverGroup string, req CreateServerRequest) (*CreateServerResponse, error) {
	if err := ValidateCreateServerRequest(req); err != nil {
		return nil, err
	}
	resp, err := s.client.Execute(ctx, false, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PostServer(ctx, trustDomain, serverGroup, &swaapi.PostServerParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out CreateServerResponse
	if err := HandleResponse(swaerrors.OpServersCreate, resp, &out, []int{http.StatusCreated, http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update patches a server's authenticator configuration.
func (s *ServersService) Update(ctx context.Context, trustDomain, serverGroup, name string, req UpdateServerRequest) (*Server, error) {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.PatchServer(ctx, trustDomain, serverGroup, name, &swaapi.PatchServerParams{Accept: acceptV2}, req)
	})
	if err != nil {
		return nil, err
	}
	var out Server
	if err := HandleResponse(swaerrors.OpServersUpdate, resp, &out, []int{http.StatusOK}); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes a server.
func (s *ServersService) Delete(ctx context.Context, trustDomain, serverGroup, name string) error {
	resp, err := s.client.Execute(ctx, true, func(ctx context.Context) (*http.Response, error) {
		return s.client.swa.DeleteServer(ctx, trustDomain, serverGroup, name, &swaapi.DeleteServerParams{Accept: acceptV2})
	})
	if err != nil {
		return err
	}
	return HandleResponse(swaerrors.OpServersDelete, resp, nil, []int{http.StatusNoContent, http.StatusOK})
}

// Apply ensures a server matching req exists within the server group, creating it
// when absent and updating its authenticator to match when present. See the
// reconcile notes in apply.go.
//
// Servers differ from the other resources in two API-level ways, both handled
// here rather than pushed onto callers: the authenticator subject is immutable
// (PATCH cannot change it, so a subject change is not propagated on the update
// path — replace the server instead), and the one-time bootstrap identifier
// (authn_id) is only returned when the server is created. On the create path the
// returned *Server therefore carries the freshly minted Name and AuthnId; on the
// update path it is the server as returned by PATCH.
func (s *ServersService) Apply(ctx context.Context, trustDomain, serverGroup string, req CreateServerRequest) (*Server, ApplyAction, error) {
	if err := ValidateCreateServerRequest(req); err != nil {
		return nil, "", err
	}
	_, err := s.Get(ctx, trustDomain, serverGroup, req.Name)
	switch {
	case err == nil:
		updReq, mErr := toUpdateServerRequest(req)
		if mErr != nil {
			return nil, "", mErr
		}
		srv, uErr := s.Update(ctx, trustDomain, serverGroup, req.Name, updReq)
		if uErr != nil {
			return nil, "", uErr
		}
		return srv, ApplyActionUpdated, nil
	case swaerrors.IsNotFound(err):
		created, cErr := s.Create(ctx, trustDomain, serverGroup, req)
		if cErr != nil {
			return nil, "", cErr
		}
		authnID := created.AuthnId
		return &Server{Name: created.Name, AuthnId: &authnID}, ApplyActionCreated, nil
	default:
		return nil, "", err
	}
}

// toUpdateServerRequest projects a create request onto the server update request.
// The server subject is immutable and is intentionally dropped; every other JWT
// authenticator field carries over. A JSON round-trip performs the projection so
// it stays resilient to field additions in the generated types.
func toUpdateServerRequest(req CreateServerRequest) (UpdateServerRequest, error) {
	var out UpdateServerRequest
	jwt, err := req.Authentication.Data.AsCreateServerJWTAuthenticationData()
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(jwt)
	if err != nil {
		return out, err
	}
	var upd swaapi.UpdateServerJWTAuthenticationData
	if err := json.Unmarshal(raw, &upd); err != nil {
		return out, err
	}
	// The subject is immutable server-side; never send it on update.
	upd.Sub = nil
	var data swaapi.UpdateServerAuthenticationInput_Data
	if err := data.FromUpdateServerJWTAuthenticationData(upd); err != nil {
		return out, err
	}
	typ := swaapi.UpdateServerAuthenticationInputType(req.Authentication.Type)
	out.Authentication = swaapi.UpdateServerAuthenticationInput{Type: &typ, Data: &data}
	return out, nil
}

// ValidateCreateServerRequest checks a server create request: a valid server name
// (1-51 characters) and a non-empty authentication type.
func ValidateCreateServerRequest(req CreateServerRequest) error {
	var v []swaerrors.FieldViolation
	serverNameRule.validate("name", req.Name, &v)
	if strings.TrimSpace(string(req.Authentication.Type)) == "" {
		v = append(v, swaerrors.FieldViolation{Field: "authentication.type", Message: "must be set (e.g. \"JWT\")"})
	}
	return swaerrors.NewValidationError(swaerrors.OpServersCreate, v)
}
