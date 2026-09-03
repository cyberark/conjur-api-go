package swafake

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	swaapi "github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swafake/internal/serverapi/swa"
)

// handler implements the generated echo ServerInterface for the SWA API
// surface against the in-memory store.
//
// Each method pulls the standard net/http pair out of the echo.Context and then
// shares the same helpers (writeJSON/writeError/decodeBody).
type handler struct {
	srv *Server
}

// ---- liveness ------------------------------------------------------------

func (h *handler) GetLivez(ctx echo.Context) error {
	writeJSON(ctx.Response(), http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// ---- trust domains -------------------------------------------------------

func (h *handler) GetTrustDomains(ctx echo.Context, params swaapi.GetTrustDomainsParams) error {
	w := ctx.Response()
	st := h.srv.store
	st.mu.RLock()
	tds := make([]swaapi.TrustDomainResponse, 0, len(st.trustDomains))
	for _, td := range st.trustDomains {
		tds = append(tds, td)
	}
	st.mu.RUnlock()
	sort.Slice(tds, func(i, j int) bool { return tds[i].Name < tds[j].Name })
	page, count := paginate(tds, params.Limit, params.Offset)
	writeJSON(w, http.StatusOK, swaapi.TrustDomainListResponse{Count: count, TrustDomains: page})
	return nil
}

func (h *handler) PostTrustDomain(ctx echo.Context, params swaapi.PostTrustDomainParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.CreateTrustDomainRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.trustDomains[req.Name]; ok {
		writeError(w, r, http.StatusConflict, "trust_domain_already_exists", "trust domain already exists")
		return nil
	}
	td := resolveTrustDomain(req, baseURL(r), time.Now().UTC())
	st.trustDomains[req.Name] = td
	writeJSON(w, http.StatusCreated, td)
	return nil
}

func (h *handler) GetTrustDomain(ctx echo.Context, name swaapi.TrustDomainName, params swaapi.GetTrustDomainParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.RLock()
	td, ok := st.trustDomains[name]
	st.mu.RUnlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "trust_domain_not_found", "trust domain not found")
		return nil
	}
	writeJSON(w, http.StatusOK, td)
	return nil
}

func (h *handler) PatchTrustDomain(ctx echo.Context, name swaapi.TrustDomainName, params swaapi.PatchTrustDomainParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.UpdateTrustDomainRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	td, ok := st.trustDomains[name]
	if !ok {
		writeError(w, r, http.StatusNotFound, "trust_domain_not_found", "trust domain not found")
		return nil
	}
	if in := req.Jwt; in != nil {
		if in.SignatureAlgorithm != nil {
			td.Jwt.SignatureAlgorithm = swaapi.JWTConfigurationSignatureAlgorithm(*in.SignatureAlgorithm)
		}
		if in.SigningKeyType != nil {
			td.Jwt.SigningKeyType = swaapi.JWTConfigurationSigningKeyType(*in.SigningKeyType)
		}
		if in.SigningKeyTtl != nil {
			td.Jwt.SigningKeyTtl = *in.SigningKeyTtl
		}
		if in.TokenTtl != nil {
			td.Jwt.TokenTtl = *in.TokenTtl
		}
	}
	if req.X509 != nil {
		td.X509.WorkloadTtl = req.X509.WorkloadTtl
	}
	td.UpdatedAt = time.Now().UTC()
	st.trustDomains[name] = td
	writeJSON(w, http.StatusOK, td)
	return nil
}

func (h *handler) DeleteTrustDomain(ctx echo.Context, name swaapi.TrustDomainName, params swaapi.DeleteTrustDomainParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.trustDomains[name]; !ok {
		writeError(w, r, http.StatusNotFound, "trust_domain_not_found", "trust domain not found")
		return nil
	}
	delete(st.trustDomains, name)
	delete(st.serverGroups, name)
	delete(st.nodeGroups, name)
	delete(st.servers, name)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- server groups -------------------------------------------------------

func (h *handler) GetServerGroups(ctx echo.Context, td swaapi.TrustDomainName, params swaapi.GetServerGroupsParams) error {
	w := ctx.Response()
	st := h.srv.store
	st.mu.RLock()
	sgs := make([]swaapi.ServerGroupResponse, 0, len(st.serverGroups[td]))
	for _, sg := range st.serverGroups[td] {
		sgs = append(sgs, sg)
	}
	st.mu.RUnlock()
	sort.Slice(sgs, func(i, j int) bool { return sgs[i].Name < sgs[j].Name })
	page, count := paginate(sgs, params.Limit, params.Offset)
	writeJSON(w, http.StatusOK, swaapi.ServerGroupListResponse{Count: count, ServerGroups: page})
	return nil
}

func (h *handler) PostServerGroup(ctx echo.Context, td swaapi.TrustDomainName, params swaapi.PostServerGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.CreateServerGroupRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.trustDomains[td]; !ok {
		writeError(w, r, http.StatusNotFound, "trust_domain_not_found", "trust domain not found")
		return nil
	}
	if _, ok := st.serverGroups[td][req.Name]; ok {
		writeError(w, r, http.StatusConflict, "server_group_already_exists", "server group already exists")
		return nil
	}
	applyGCPAudienceDefault(req.Attestation)
	now := time.Now().UTC()
	sg := swaapi.ServerGroupResponse{
		Name:            req.Name,
		TrustDomainName: td,
		Description:     req.Description,
		Attestation:     req.Attestation,
		NodeAttestation: req.NodeAttestation,
		CreatedAt:       &now,
		UpdatedAt:       &now,
	}
	if st.serverGroups[td] == nil {
		st.serverGroups[td] = map[string]swaapi.ServerGroupResponse{}
	}
	st.serverGroups[td][req.Name] = sg
	writeJSON(w, http.StatusCreated, sg)
	return nil
}

func (h *handler) GetServerGroup(ctx echo.Context, td swaapi.TrustDomainName, name swaapi.ServerGroupName, params swaapi.GetServerGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.RLock()
	sg, ok := st.serverGroups[td][name]
	st.mu.RUnlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "server_group_not_found", "server group not found")
		return nil
	}
	writeJSON(w, http.StatusOK, sg)
	return nil
}

func (h *handler) PatchServerGroup(ctx echo.Context, td swaapi.TrustDomainName, name swaapi.ServerGroupName, params swaapi.PatchServerGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.UpdateServerGroupRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	sg, ok := st.serverGroups[td][name]
	if !ok {
		writeError(w, r, http.StatusNotFound, "server_group_not_found", "server group not found")
		return nil
	}
	if req.Description != nil {
		sg.Description = req.Description
	}
	if req.Attestation != nil {
		applyGCPAudienceDefault(req.Attestation)
		sg.Attestation = req.Attestation
	}
	if req.NodeAttestation != nil {
		sg.NodeAttestation = req.NodeAttestation
	}
	now := time.Now().UTC()
	sg.UpdatedAt = &now
	st.serverGroups[td][name] = sg
	writeJSON(w, http.StatusOK, sg)
	return nil
}

func (h *handler) DeleteServerGroup(ctx echo.Context, td swaapi.TrustDomainName, name swaapi.ServerGroupName, params swaapi.DeleteServerGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.serverGroups[td][name]; !ok {
		writeError(w, r, http.StatusNotFound, "server_group_not_found", "server group not found")
		return nil
	}
	delete(st.serverGroups[td], name)
	if st.nodeGroups[td] != nil {
		delete(st.nodeGroups[td], name)
	}
	if st.servers[td] != nil {
		delete(st.servers[td], name)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- node groups ---------------------------------------------------------

func (h *handler) GetNodeGroups(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, params swaapi.GetNodeGroupsParams) error {
	w := ctx.Response()
	st := h.srv.store
	st.mu.RLock()
	ngs := make([]swaapi.NodeGroupResponse, 0, len(st.nodeGroups[td][sg]))
	for _, ng := range st.nodeGroups[td][sg] {
		ngs = append(ngs, ng)
	}
	st.mu.RUnlock()
	sort.Slice(ngs, func(i, j int) bool { return ngs[i].Name < ngs[j].Name })
	page, count := paginate(ngs, params.Limit, params.Offset)
	writeJSON(w, http.StatusOK, swaapi.NodeGroupListResponse{Count: count, NodeGroups: page})
	return nil
}

func (h *handler) PostNodeGroups(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, params swaapi.PostNodeGroupsParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.NodeGroupCreateRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.serverGroups[td][sg]; !ok {
		writeError(w, r, http.StatusNotFound, "server_group_not_found", "server group not found")
		return nil
	}
	if _, ok := st.nodeGroups[td][sg][req.Name]; ok {
		writeError(w, r, http.StatusConflict, "node_group_already_exists", "node group already exists")
		return nil
	}
	wt := swaapi.NodeGroupResponseWorkloadType(req.WorkloadType)
	now := time.Now().UTC()
	ng := swaapi.NodeGroupResponse{
		Name:                  req.Name,
		Description:           req.Description,
		WorkloadType:          wt,
		WorkloadConfiguration: normalizeWorkloadConfiguration(req.WorkloadConfiguration, wt),
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if st.nodeGroups[td] == nil {
		st.nodeGroups[td] = map[string]map[string]swaapi.NodeGroupResponse{}
	}
	if st.nodeGroups[td][sg] == nil {
		st.nodeGroups[td][sg] = map[string]swaapi.NodeGroupResponse{}
	}
	st.nodeGroups[td][sg][req.Name] = ng
	writeJSON(w, http.StatusCreated, ng)
	return nil
}

func (h *handler) GetNodeGroup(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.NodeGroupName, params swaapi.GetNodeGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.RLock()
	ng, ok := st.nodeGroups[td][sg][name]
	st.mu.RUnlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "node_group_not_found", "node group not found")
		return nil
	}
	writeJSON(w, http.StatusOK, ng)
	return nil
}

func (h *handler) PatchNodeGroup(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.NodeGroupName, params swaapi.PatchNodeGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.NodeGroupUpdateRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	ng, ok := st.nodeGroups[td][sg][name]
	if !ok {
		writeError(w, r, http.StatusNotFound, "node_group_not_found", "node group not found")
		return nil
	}
	if req.Description != nil {
		ng.Description = req.Description
	}
	// A present workload_configuration (even empty) means "set to this / reset to
	// defaults"; omitting it leaves the existing configuration untouched.
	if req.WorkloadConfiguration != nil {
		ng.WorkloadConfiguration = normalizeWorkloadConfiguration(req.WorkloadConfiguration, ng.WorkloadType)
	}
	ng.UpdatedAt = time.Now().UTC()
	st.nodeGroups[td][sg][name] = ng
	writeJSON(w, http.StatusOK, ng)
	return nil
}

func (h *handler) DeleteNodeGroup(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.NodeGroupName, params swaapi.DeleteNodeGroupParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.nodeGroups[td][sg][name]; !ok {
		writeError(w, r, http.StatusNotFound, "node_group_not_found", "node group not found")
		return nil
	}
	delete(st.nodeGroups[td][sg], name)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- servers -------------------------------------------------------------

func (h *handler) GetServers(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, params swaapi.GetServersParams) error {
	w := ctx.Response()
	st := h.srv.store
	st.mu.RLock()
	servers := make([]swaapi.ServerResponse, 0, len(st.servers[td][sg]))
	for _, s := range st.servers[td][sg] {
		servers = append(servers, s)
	}
	st.mu.RUnlock()
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	page, count := paginate(servers, params.Limit, params.Offset)
	writeJSON(w, http.StatusOK, swaapi.ServerListResponse{Count: count, Components: page})
	return nil
}

func (h *handler) PostServer(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, params swaapi.PostServerParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.CreateServerRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.serverGroups[td][sg]; !ok {
		writeError(w, r, http.StatusNotFound, "server_group_not_found", "server group not found")
		return nil
	}
	if _, ok := st.servers[td][sg][req.Name]; ok {
		writeError(w, r, http.StatusConflict, "server_already_exists", "server already exists")
		return nil
	}
	authnID := newAuthnID()
	sgName := sg
	// Persist a server representation for later Get/List.
	stored := swaapi.ServerResponse{
		Name:            req.Name,
		ServerGroupName: &sgName,
		AuthnId:         &authnID,
	}
	if st.servers[td] == nil {
		st.servers[td] = map[string]map[string]swaapi.ServerResponse{}
	}
	if st.servers[td][sg] == nil {
		st.servers[td][sg] = map[string]swaapi.ServerResponse{}
	}
	st.servers[td][sg][req.Name] = stored
	writeJSON(w, http.StatusCreated, swaapi.CreateServerResponse{
		Name:           req.Name,
		AuthnId:        authnID,
		Authentication: req.Authentication,
	})
	return nil
}

func (h *handler) GetServer(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.ServerName, params swaapi.GetServerParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.RLock()
	s, ok := st.servers[td][sg][name]
	st.mu.RUnlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "server_not_found", "server not found")
		return nil
	}
	writeJSON(w, http.StatusOK, s)
	return nil
}

func (h *handler) PatchServer(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.ServerName, params swaapi.PatchServerParams) error {
	w, r := ctx.Response(), ctx.Request()
	var req swaapi.UpdateServerRequest
	if !decodeBody(w, r, &req) {
		return nil
	}
	st := h.srv.store
	st.mu.RLock()
	s, ok := st.servers[td][sg][name]
	st.mu.RUnlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "server_not_found", "server not found")
		return nil
	}
	// The authenticator subject is immutable server-side; the fake simply echoes
	// the current server (the SDK never sends the subject on update).
	writeJSON(w, http.StatusOK, s)
	return nil
}

func (h *handler) DeleteServer(ctx echo.Context, td swaapi.TrustDomainName, sg swaapi.ServerGroupName, name swaapi.ServerName, params swaapi.DeleteServerParams) error {
	w, r := ctx.Response(), ctx.Request()
	st := h.srv.store
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.servers[td][sg][name]; !ok {
		writeError(w, r, http.StatusNotFound, "server_not_found", "server not found")
		return nil
	}
	delete(st.servers[td][sg], name)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- well-known / discovery ---------------------------------------------

func (h *handler) GetCaBundles(ctx echo.Context, td swaapi.TrustDomainName, params swaapi.GetCaBundlesParams) error {
	w := ctx.Response()
	st := h.srv.store
	st.mu.RLock()
	bundles := append([][]byte(nil), st.bundles...)
	st.mu.RUnlock()
	if params.Format != nil && *params.Format == swaapi.Pem {
		var pemBuf strings.Builder
		for _, der := range bundles {
			pemBuf.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
		}
		writeJSON(w, http.StatusOK, map[string]string{"bundle": pemBuf.String()})
		return nil
	}
	if bundles == nil {
		bundles = [][]byte{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": bundles})
	return nil
}

func (h *handler) GetJwks(ctx echo.Context, td swaapi.TrustDomainName) error {
	writeJSON(ctx.Response(), http.StatusOK, swaapi.JWKS{Keys: []swaapi.JWK{}})
	return nil
}

func (h *handler) GetSpiffeBundle(ctx echo.Context, td swaapi.TrustDomainName) error {
	// minimal empty SPIFFE trust bundle; seed real keys here if a consumer test needs a populated bundle.
	writeJSON(ctx.Response(), http.StatusOK, map[string]any{
		"spiffe_sequence":     0,
		"spiffe_refresh_hint": 3600,
		"keys":                []any{},
	})
	return nil
}

func (h *handler) GetOpenidConfiguration(ctx echo.Context, td swaapi.TrustDomainName) error {
	r := ctx.Request()
	issuer := baseURL(r) + "/api/swa/trust-domains/" + td
	writeJSON(ctx.Response(), http.StatusOK, swaapi.OpenIDConfiguration{
		Issuer:                           issuer,
		JwksUri:                          issuer + "/.well-known/jwks",
		IdTokenSigningAlgValuesSupported: []string{"ES256"},
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
	})
	return nil
}

// newAuthnID returns an opaque base64-encoded identifier, mirroring the shape of
// the server-minted authn_id.
func newAuthnID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}
