package swa

import (
	"fmt"
	"regexp"

	"github.com/cyberark/conjur-api-go/internal/swa-sdk-go/swaerrors"
)

// Client-side request validation mirrors the control plane's own rules so that
// every consumer fails fast, locally, and with the same diagnostics — instead of
// each client rediscovering the contract or only learning about a bad request
// after a network round-trip. The per-resource Validate* functions live with
// their resource (e.g. ValidateCreateServerGroupRequest in server_groups.go) and
// are invoked automatically by the Create methods and by Apply; they are also
// exported so callers can validate speculatively (e.g. a Terraform provider's
// plan phase, or a CLI's --dry-run).
//
// The violation and error types themselves (swaerrors.FieldViolation,
// swaerrors.ValidationError) live in the swaerrors subpackage alongside the rest
// of the SDK's error surface. This file holds only the shared validation
// vocabulary used to build them.

// nameCharset is the shared character class for SWA resource names: letters,
// numbers, periods, underscores, and hyphens.
const nameCharset = `A-Za-z0-9._-`

// nameRule is the single source of truth for an SWA resource-name constraint.
// The matching pattern and the length used to phrase the error message are both
// derived from maxLen, so they can never drift — the reviewer's concern about
// the name-length check being specified in two places (the regexp and a separate
// literal) does not apply. The per-resource Validate* functions stay hand-written
// for discoverability, but they all defer to a shared rule here.
type nameRule struct {
	maxLen  int
	pattern *regexp.Regexp
}

func newNameRule(maxLen int) nameRule {
	return nameRule{
		maxLen:  maxLen,
		pattern: regexp.MustCompile(fmt.Sprintf(`^[%s]{1,%d}$`, nameCharset, maxLen)),
	}
}

// Resource-name length limits differ by resource: trust domains, server groups,
// and node groups allow up to 60 characters; servers allow up to 51.
var (
	resourceNameRule = newNameRule(60)
	serverNameRule   = newNameRule(51)
)

// validate appends a violation for field when name breaks the rule.
func (r nameRule) validate(field, name string, into *[]swaerrors.FieldViolation) {
	if !r.pattern.MatchString(name) {
		*into = append(*into, swaerrors.FieldViolation{
			Field:   field,
			Message: fmt.Sprintf("must be 1-%d characters using only letters, numbers, periods, underscores, and hyphens", r.maxLen),
		})
	}
}
