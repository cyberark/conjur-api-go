// Package swafake provides a spec-faithful, in-process fake of the SWA API
// for use in tests. It is the server-side counterpart to the
// swatest package: where swatest fakes the SDK's Go interfaces, swafake fakes
// the HTTP API itself, so the full client stack (auth headers, retry/backoff,
// query encoding, response parsing) runs end to end over loopback.
//
// The fake is driven by the same OpenAPI specifications as the real service.
// Each surface's handler is bound to the generated ServerInterface with a
// compile-time assertion (see the var _ ...ServerInterface blocks), so if the
// spec grows a new endpoint the fake fails to build until it is implemented —
// the fake can never silently drift from the contract.
//
// Typical use:
//
//	fake := swafake.New(swafake.WithTrustDomain("prod.example.com"))
//	defer fake.Close()
//
//	client := fake.Client() // a *swa.Client pointed at the fake
//	sg, _, err := client.ServerGroups().Apply(ctx, "prod.example.com", swa.CreateServerGroupRequest{...})
//
// State is held in an in-memory store seeded via the With* options and mutated
// by requests. Faults can be injected to exercise error paths, and every
// request is captured for assertions:
//
//	fake := swafake.New(swafake.WithError(http.MethodGet, "/server-groups/", http.StatusServiceUnavailable, "unavailable", "try later"))
//	...
//	for _, r := range fake.Requests() { ... }
//
// The zero request set and store can be cleared with Reset.
package swafake
