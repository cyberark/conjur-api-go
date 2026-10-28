package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// AnnotationKind is the kind of resource an annotation lives on.
type AnnotationKind string

// annotationsEnvelope decodes the annotations of any annotated resource. A
// workload, group and branch all carry them in the same top-level field, both
// when read and in a PATCH body.
type annotationsEnvelope struct {
	Annotations map[string]string `json:"annotations"`
}

const (
	AnnotationKindWorkload AnnotationKind = "workload"
	AnnotationKindGroup    AnnotationKind = "group"
	AnnotationKindBranch   AnnotationKind = "branch"
)

var annotationKindPrefix = map[AnnotationKind]string{
	AnnotationKindWorkload: "workloads",
	AnnotationKindGroup:    "groups",
	AnnotationKindBranch:   "branches",
}

// annotationKindHeader is the API version header each kind's resource routes
// use: workloads are on v2, groups and branches still on v2beta.
var annotationKindHeader = map[AnnotationKind]string{
	AnnotationKindWorkload: v2APIHeader,
	AnnotationKindGroup:    v2APIHeaderBeta,
	AnnotationKindBranch:   v2APIHeaderBeta,
}

// The server's length limits for an annotation, in characters.
const (
	maxAnnotationNameLength  = 128
	maxAnnotationValueLength = 512
)

// reservedWorkloadAnnotationPrefixes start the workload annotations that hold
// authn descriptors. With type and authn/api-key they are workload fields, so
// the server refuses to set or delete them as annotations.
var reservedWorkloadAnnotationPrefixes = []string{
	"authn-jwt/", "authn-iam/", "authn-gcp/", "authn-azure/", "authn-cert/",
}

// SupportedAnnotationKinds returns the kinds the annotation methods accept,
// sorted.
func SupportedAnnotationKinds() []AnnotationKind {
	kinds := make([]AnnotationKind, 0, len(annotationKindPrefix))
	for k := range annotationKindPrefix {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

// SupportedAnnotationKindNames returns SupportedAnnotationKinds as strings, for
// callers that display the kinds.
func SupportedAnnotationKindNames() []string {
	kinds := SupportedAnnotationKinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return names
}

// SetAnnotation sets one annotation on a workload, group or branch, creating
// it or replacing its value.
//
// The V2 API has no route for a single annotation, so this patches the
// resource with only this annotation. The server merges annotations one key at
// a time and leaves the others alone, so concurrent calls for different names
// cannot overwrite each other. For the same existing name the last write wins,
// and of two concurrent creates of the same name one gets a 409. The server
// allows at most 20 annotations per resource.
//
// Before sending, this refuses what the server would: an empty or blank value
// (to clear an annotation, delete it), a name or value holding <, > or ', a
// name over 128 or a value over 512 characters, and on a workload the names
// that are workload fields (type, authn/api-key, authn-<type>/...). It also
// refuses the names DeleteAnnotation refuses, which could not be deleted.
func (c *ClientV2) SetAnnotation(kind AnnotationKind, identifier string, annotationName string, value string) error {
	if err := c.gateAnnotationKind(kind); err != nil {
		return err
	}

	req, err := c.SetAnnotationRequest(kind, identifier, annotationName, value)
	if err != nil {
		return err
	}

	_, err = submitAndReadData(c, req)
	return err
}

// ListAnnotations returns every annotation on a workload, group or branch.
// There is no annotation list route, so this reads the resource and returns its
// annotations. A resource without annotations gives an empty, non-nil map.
func (c *ClientV2) ListAnnotations(kind AnnotationKind, identifier string) (map[string]string, error) {
	if err := c.gateAnnotationKind(kind); err != nil {
		return nil, err
	}

	req, err := c.ListAnnotationsRequest(kind, identifier)
	if err != nil {
		return nil, err
	}

	envelope, err := submitAndUnmarshal[annotationsEnvelope](c, req)
	if err != nil {
		return nil, err
	}
	if envelope.Annotations == nil {
		return map[string]string{}, nil
	}
	return envelope.Annotations, nil
}

// GetAnnotation returns the value of one annotation on a workload, group or
// branch. There is no annotation get route, so this reads the resource. A
// missing annotation returns an HTTP 404 *response.ConjurError, the same as a
// missing resource and as DeleteAnnotation, so callers handle not-found once.
// It refuses the names DeleteAnnotation refuses.
func (c *ClientV2) GetAnnotation(kind AnnotationKind, identifier string, annotationName string) (string, error) {
	if err := checkAnnotationName(annotationName); err != nil {
		return "", err
	}

	annotations, err := c.ListAnnotations(kind, identifier)
	if err != nil {
		return "", err
	}

	value, ok := annotations[annotationName]
	if !ok {
		// Shaped like a server error, so Error() reads "<status>. <reason>.".
		return "", &response.ConjurError{
			Code:    http.StatusNotFound,
			Message: fmt.Sprintf("%d %s", http.StatusNotFound, http.StatusText(http.StatusNotFound)),
			Details: &response.ConjurErrorDetails{
				Code:    "not_found",
				Message: fmt.Sprintf("Annotation '%s' not found on %s '%s'", annotationName, kind, identifier),
			},
		}
	}
	return value, nil
}

// DeleteAnnotation removes one annotation from a workload, group or branch.
// It is the only operation with its own V2 route; SetAnnotation, GetAnnotation
// and ListAnnotations go through the resource. On Self-Hosted only group
// annotations are supported. A missing annotation returns an HTTP 404.
//
// It refuses the names "." and "..", and any holding "../" or "..\": the
// server deletes the resource itself for "..", and the SaaS gateway refuses
// the others. On a workload the server refuses to delete the names that are
// workload fields with a 422.
func (c *ClientV2) DeleteAnnotation(kind AnnotationKind, identifier string, annotationName string) error {
	if err := c.gateAnnotationKind(kind); err != nil {
		return err
	}

	req, err := c.DeleteAnnotationRequest(kind, identifier, annotationName)
	if err != nil {
		return err
	}

	return submitAndEmpty(c, req)
}

// SetAnnotationRequest builds the PATCH that sets one annotation. The name
// travels in the JSON body, not the URL, so it needs no path escaping.
func (c *ClientV2) SetAnnotationRequest(kind AnnotationKind, identifier string, annotationName string, value string) (*http.Request, error) {
	if err := checkAnnotationToSet(kind, annotationName, value); err != nil {
		return nil, err
	}

	resourceURL, err := c.annotatedResourceURL(kind, identifier)
	if err != nil {
		return nil, err
	}

	payload := annotationsEnvelope{Annotations: map[string]string{annotationName: value}}
	return newV2JSONRequest(http.MethodPatch, resourceURL, payload, annotationKindHeader[kind])
}

// ListAnnotationsRequest builds the GET that reads the annotated resource.
func (c *ClientV2) ListAnnotationsRequest(kind AnnotationKind, identifier string) (*http.Request, error) {
	resourceURL, err := c.annotatedResourceURL(kind, identifier)
	if err != nil {
		return nil, err
	}

	return newV2Request(http.MethodGet, resourceURL, annotationKindHeader[kind])
}

func (c *ClientV2) DeleteAnnotationRequest(kind AnnotationKind, identifier string, annotationName string) (*http.Request, error) {
	if err := c.gateAnnotationKind(kind); err != nil {
		return nil, err
	}
	if _, ok := annotationKindPrefix[kind]; !ok {
		return nil, fmt.Errorf(
			"unsupported annotation kind %q (supported: %s)",
			kind, strings.Join(SupportedAnnotationKindNames(), ", "),
		)
	}
	if identifier == "" {
		return nil, fmt.Errorf("Must specify a resource identifier")
	}
	if err := checkAnnotationName(annotationName); err != nil {
		return nil, err
	}

	if kind == AnnotationKindGroup {
		return c.DeleteGroupAnnotationRequest(identifier, annotationName)
	}

	// The name is one segment, so a "/" in it is sent as %2F.
	escapedName, err := escapePathSegments("Annotation name", []string{annotationName})
	if err != nil {
		return nil, err
	}

	fullURL, err := c.annotatedResourceURL(kind, identifier, "annotations", escapedName[0])
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)
	return req, nil
}

// checkAnnotationName refuses the names DeleteAnnotation cannot send. The
// server resolves a "." or ".." name against the URL, so deleting the
// annotation ".." deletes the resource itself, and the SaaS gateway refuses
// a name holding "../" or "..\" with a 403.
func checkAnnotationName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("Must specify an annotation name")
	case strings.TrimSpace(name) == "":
		return fmt.Errorf("Annotation name must not be only whitespace")
	case name == "." || name == "..":
		return fmt.Errorf("Annotation name must not be %q", name)
	case strings.Contains(name, "../") || strings.Contains(name, `..\`):
		return fmt.Errorf(`Annotation name must not contain "../" or "..\"`)
	}
	return nil
}

// checkAnnotationToSet refuses what the server would refuse to set, so it
// fails before a request is sent. The cap of 20 annotations per resource is
// left to the server.
func checkAnnotationToSet(kind AnnotationKind, name, value string) error {
	var errs []error
	if err := checkAnnotationName(name); err != nil {
		errs = append(errs, err)
	}
	if n := utf8.RuneCountInString(name); n > maxAnnotationNameLength {
		errs = append(errs, fmt.Errorf("Annotation name is %d characters, more than the limit of %d", n, maxAnnotationNameLength))
	}
	if strings.ContainsAny(name, "<>'") {
		errs = append(errs, fmt.Errorf("Annotation name must not contain <, > or '"))
	}
	if kind == AnnotationKindWorkload && isReservedWorkloadAnnotation(name) {
		errs = append(errs, fmt.Errorf("Annotation name %q is reserved on workloads for workload fields", name))
	}

	switch {
	case value == "":
		errs = append(errs, fmt.Errorf("Must specify an annotation value; to remove an annotation, delete it"))
	case strings.TrimSpace(value) == "":
		errs = append(errs, fmt.Errorf("Annotation value must not be only whitespace; to remove an annotation, delete it"))
	}
	if n := utf8.RuneCountInString(value); n > maxAnnotationValueLength {
		errs = append(errs, fmt.Errorf("Annotation value is %d characters, more than the limit of %d", n, maxAnnotationValueLength))
	}
	if strings.ContainsAny(value, "<>'") {
		errs = append(errs, fmt.Errorf("Annotation value must not contain <, > or '"))
	}
	return errors.Join(errs...)
}

func isReservedWorkloadAnnotation(name string) bool {
	if name == "type" || name == "authn/api-key" {
		return true
	}
	for _, prefix := range reservedWorkloadAnnotationPrefixes {
		if len(name) > len(prefix) && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// gateAnnotationKind refuses branch annotations where the platform has no route
// for them. Every annotation operation and request builder applies it, not
// only delete, so a kind that cannot be deleted on a platform cannot be set
// there either. The builders need it because SubmitRequest lets branch routes
// through on Self-Hosted.
func (c *ClientV2) gateAnnotationKind(kind AnnotationKind) error {
	if kind == AnnotationKindBranch {
		return c.checkCapability(contract.CapabilityBranchAnnotationsV2)
	}
	return nil
}

// annotatedResourceURL builds the URL of the resource an annotation lives on,
// escaping each segment of the identifier. The resource builders are not used
// for this: branchURL joins the identifier unescaped, so "data/../x" would
// address a different branch.
func (c *ClientV2) annotatedResourceURL(kind AnnotationKind, identifier string, extra ...string) (string, error) {
	if err := c.gateAnnotationKind(kind); err != nil {
		return "", err
	}
	prefix, ok := annotationKindPrefix[kind]
	if !ok {
		return "", fmt.Errorf(
			"unsupported annotation kind %q (supported: %s)",
			kind, strings.Join(SupportedAnnotationKindNames(), ", "),
		)
	}
	if identifier == "" {
		return "", fmt.Errorf("Must specify a resource identifier")
	}

	escapedID, err := escapeAnnotationIdentifier("Resource identifier", identifier)
	if err != nil {
		return "", err
	}

	components := []string{prefix}
	if seg := c.annotationAccountSegment(kind); seg != "" {
		components = append(components, seg)
	}
	components = append(components, escapedID)
	components = append(components, extra...)

	return makeRouterURL(c.config.ApplianceURL, components...).String(), nil
}

// annotationAccountSegment returns the account segment for Self-Hosted group
// and branch URLs, or "".
func (c *ClientV2) annotationAccountSegment(kind AnnotationKind) string {
	if c.config.IsSaaS() || kind == AnnotationKindWorkload {
		return ""
	}
	return c.config.Account
}

// escapeAnnotationIdentifier escapes each segment of a slash-separated
// identifier, rejecting empty, "." and ".." ones.
func escapeAnnotationIdentifier(what, identifier string) (string, error) {
	segments, err := escapePathSegments(what, strings.Split(identifier, "/"))
	if err != nil {
		return "", err
	}
	return strings.Join(segments, "/"), nil
}
