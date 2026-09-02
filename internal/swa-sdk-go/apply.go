package swa

// The Apply methods (defined alongside each resource's service, e.g. in
// server_groups.go) provide a small, declarative reconcile layer on top of the
// imperative Get/Create/Update primitives: give Apply the *desired* full state of
// a resource and it ensures the resource exists and matches, creating it when
// absent and updating it when present. This is the idempotent "ensure" operation
// that imperative clients (CLIs, controllers, Terraform-style providers, bootstrap
// scripts) would otherwise each reimplement — and getting it wrong is what caused
// stale-state bugs downstream. Putting it in the SDK means every client reconciles
// identically, including the control plane's reset semantics (see
// ResetWorkloadConfiguration).
//
// Apply takes the resource's *create* request as the desired state. When the
// resource already exists it is mapped to the corresponding update request (via
// the toUpdate* helpers next to each service); any field the update endpoint
// cannot change (name, workload type, server subject) is simply not sent. Apply
// always issues an update when the resource exists — the control plane's update
// endpoints are idempotent — so it does not attempt fragile client-side "no diff"
// detection. "Idempotent" here means idempotent in effect: repeated Apply calls
// are safe and converge to the same state, though server-side bookkeeping such as
// updated_at and audit history still advances on each call.
//
// This file holds only the shared vocabulary for the pattern; the per-resource
// Apply methods live with their resource so everything about a resource is in one
// place.

// ApplyAction reports what Apply did to converge a resource.
type ApplyAction string

const (
	// ApplyActionCreated means the resource did not exist and was created.
	ApplyActionCreated ApplyAction = "created"
	// ApplyActionUpdated means the resource already existed and was updated to
	// match the desired state.
	ApplyActionUpdated ApplyAction = "updated"
)
