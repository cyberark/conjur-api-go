package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
)

// AuthnDescriptor describes an authenticator for a workload. Data is a
// raw map (structure varies by Type) sent flat to the server without
// a wrapper key: {"type": "jwt", "data": {"claim": "value"}}.
type AuthnDescriptor struct {
	Type      string         `json:"type"`
	ServiceID string         `json:"service_id,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

type Workload struct {
	Name             string            `json:"name"`
	Branch           string            `json:"branch"`
	Type             string            `json:"type,omitempty"`
	Owner            *Owner            `json:"owner,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors"`
	RestrictedTo     []string          `json:"restricted_to,omitempty"`

	// Server-filled attributes returned by GET/PATCH but never sent on create.
	// Carried on Workload rather than a separate response type
	// since the response here is just a superset of the request
	// All are omitempty, so CreateWorkload payloads are unaffected and a
	// read-back Workload keeps the values the server filled in.
	//
	// AuthenticationSource is also settable via WorkloadFields on PATCH, so
	// it's exposed here for callers to read back. IdentitySource and
	// CreatedAt are read-only.
	AuthenticationSource string `json:"authentication_source,omitempty"`
	IdentitySource       string `json:"identity_source,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
}

// WorkloadFields is the PATCH request body. Unset attributes are unchanged
// on the server.
//
// The server's update semantics are not the same for every attribute, and not
// what the shared endpoint suggests:
//
//   - AuthnDescriptors replaces the whole array, and each descriptor's Data with
//     it. Leaving the attribute unset keeps the existing descriptors; sending a
//     shorter array deletes the ones left out.
//   - Annotations merges. A key absent from the map keeps whatever value the
//     server holds, so an annotation cannot be removed through this endpoint.
//   - RestrictedTo replaces. Entries are normalized server-side, so "1.2.3.4"
//     reads back as "1.2.3.4/32".
type WorkloadFields struct {
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors,omitempty"`

	// RestrictedTo is a pointer so removing every CIDR restriction is
	// expressible: nil omits the attribute, leaving the server's value alone,
	// while a pointer to an empty slice sends "restricted_to": [] - omitempty
	// tests the pointer, not the slice, so the empty slice still reaches the
	// wire. A plain []string can't express both, since an empty slice is
	// indistinguishable from a nil one under omitempty, and without it a nil
	// slice sends null, which the server rejects with a 422.
	RestrictedTo *[]string `json:"restricted_to,omitempty"`

	AuthenticationSource string `json:"authentication_source,omitempty"`
}

func (c *ClientV2) CreateWorkload(workload Workload) ([]byte, error) {
	req, err := c.CreateWorkloadRequest(workload)
	if err != nil {
		return nil, err
	}

	return submitAndReadData(c, req)
}

// DeleteWorkload deletes a workload.
func (c *ClientV2) DeleteWorkload(workloadID string) ([]byte, error) {
	req, err := c.DeleteWorkloadRequest(workloadID)
	if err != nil {
		return nil, err
	}

	return submitAndReadData(c, req)
}

// CreateWorkloadRequest builds a request to create a workload.
func (c *ClientV2) CreateWorkloadRequest(workload Workload) (*http.Request, error) {
	if err := workload.Validate(); err != nil {
		return nil, err
	}

	if len(workload.AuthnDescriptors) == 0 {
		return nil, fmt.Errorf("Must specify at least one authenticator in authn_descriptors")
	}
	if err := validateAuthnDescriptors(workload.AuthnDescriptors); err != nil {
		return nil, err
	}

	// Default type
	if workload.Type == "" {
		workload.Type = "other"
	}

	return newV2JSONRequest(http.MethodPost, c.workloadsURL(), workload, v2APIHeader)
}

// validateAuthnDescriptors checks the one structural constraint that makes a
// descriptor unsendable: a missing type. Server-side policy - how many
// descriptors are allowed, and which types may repeat - is deliberately left
// to the server, so raising a limit there doesn't require a release of this
// library and a bump in every consumer that pins it.
func validateAuthnDescriptors(descriptors []AuthnDescriptor) error {
	var errs []error
	for i, d := range descriptors {
		if d.Type == "" {
			errs = append(errs, fmt.Errorf("authn_descriptors[%d] missing type", i))
		}
	}
	return errors.Join(errs...)
}

// DeleteWorkloadRequest builds a request to delete a workload.
func (c *ClientV2) DeleteWorkloadRequest(identifier string) (*http.Request, error) {
	reqURL, err := c.workloadURL(identifier)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodDelete, reqURL, v2APIHeader)
}

// GetWorkload reads a workload and returns it as the server has it, including
// the attributes the server fills in itself.
func (c *ClientV2) GetWorkload(identifier string) (*Workload, error) {
	req, err := c.GetWorkloadRequest(identifier)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[Workload](c, req)
}

// GetWorkloadRequest builds a request to read a single workload
// (GET /workloads/<identifier>).
func (c *ClientV2) GetWorkloadRequest(identifier string) (*http.Request, error) {
	reqURL, err := c.workloadURL(identifier)
	if err != nil {
		return nil, err
	}
	return newV2Request(http.MethodGet, reqURL, v2APIHeader)
}

// UpdateWorkload patches attributes; unset ones remain unchanged.
func (c *ClientV2) UpdateWorkload(identifier string, update WorkloadFields) (*Workload, error) {
	req, err := c.UpdateWorkloadRequest(identifier, update)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[Workload](c, req)
}

// UpdateWorkloadRequest builds a request to partially update a workload
// (PATCH). Attributes left unset on update are left unchanged by the server.
func (c *ClientV2) UpdateWorkloadRequest(identifier string, update WorkloadFields) (*http.Request, error) {
	if err := validateAuthnDescriptors(update.AuthnDescriptors); err != nil {
		return nil, err
	}

	reqURL, err := c.workloadURL(identifier)
	if err != nil {
		return nil, err
	}
	return newV2JSONRequest(http.MethodPatch, reqURL, update, v2APIHeader)
}

// authnDescriptorResponse is the response envelope for
// PATCH /workloads/<identifier>/authn_descriptors/<type>/<serviceID>, which
// returns the single updated descriptor rather than the whole workload.
type authnDescriptorResponse struct {
	AuthnDescriptor AuthnDescriptor `json:"authn_descriptor"`
}

// UpdateAuthnDescriptor updates the data of a single authn descriptor on a
// workload and returns the updated descriptor. descriptor.Type and
// descriptor.ServiceID address the descriptor in the URL; only
// descriptor.Data is sent as the request body, and the server merges it into
// the existing map rather than replacing it.
func (c *ClientV2) UpdateAuthnDescriptor(identifier string, descriptor AuthnDescriptor) (*AuthnDescriptor, error) {
	req, err := c.UpdateAuthnDescriptorRequest(identifier, descriptor)
	if err != nil {
		return nil, err
	}

	resp, err := submitAndUnmarshal[authnDescriptorResponse](c, req)
	if err != nil {
		return nil, err
	}
	return &resp.AuthnDescriptor, nil
}

// UpdateAuthnDescriptorRequest builds a request to update a single authn
// descriptor's data (PATCH /workloads/<identifier>/authn_descriptors/<type>/<serviceID>).
// The server merges data into the existing map rather than replacing it.
func (c *ClientV2) UpdateAuthnDescriptorRequest(identifier string, descriptor AuthnDescriptor) (*http.Request, error) {
	if err := descriptor.validateAsUpdateTarget(); err != nil {
		return nil, err
	}

	reqURL, err := c.workloadURL(identifier, "authn_descriptors", descriptor.Type, descriptor.ServiceID)
	if err != nil {
		return nil, err
	}
	return newV2JSONRequest(http.MethodPatch, reqURL, descriptor.Data, v2APIHeader)
}

func (w Workload) Validate() error {
	var errs []error
	if w.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Branch"))
	}
	if w.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Name"))
	}
	return errors.Join(errs...)
}

// validateAsUpdateTarget checks the fields needed to address an existing
// descriptor and update it. ServiceID is optional when creating a descriptor
// (api_key has none) but required here, since it is a URL path component.
func (d AuthnDescriptor) validateAsUpdateTarget() error {
	var errs []error
	if d.Type == "" {
		errs = append(errs, fmt.Errorf("Must specify an authn descriptor type"))
	}
	if d.ServiceID == "" {
		errs = append(errs, fmt.Errorf("Must specify an authn descriptor service ID"))
	}
	// An empty-map PATCH is a server-side no-op, not a way to clear a
	// descriptor's data, so accepting it here would mislead callers.
	if len(d.Data) == 0 {
		errs = append(errs, fmt.Errorf("Must specify authn descriptor data"))
	}
	return errors.Join(errs...)
}

// workloadURL builds /workloads/<identifier>[/extra...]. identifier is
// escaped as a single path segment, so any "/" in it - including the one
// separating branch from name - becomes %2F rather than a real separator.
// The server percent-decodes and reads everything after /workloads/ as one
// identifier, so this reaches the same resource while keeping caller input
// out of reach of path.Join's "." and ".." resolution. extra components are
// escaped here too, so callers must not pre-escape them.
func (c *ClientV2) workloadURL(identifier string, extra ...string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("Must specify a Workload ID")
	}

	segments, err := escapePathSegments("Workload URL", append([]string{identifier}, extra...))
	if err != nil {
		return "", err
	}
	return makeRouterURL(c.config.ApplianceURL, append([]string{"workloads"}, segments...)...).String(), nil
}

// workloadsURL addresses the /workloads collection rather than a single
// workload.
func (c *ClientV2) workloadsURL() string {
	return makeRouterURL(c.config.ApplianceURL, "workloads").String()
}
