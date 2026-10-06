package conjurapi

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type SafeDetails struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Replicated bool   `json:"replicated"`
}

type ListSafeSecretParams struct {
	Limit  int
	Offset int
	Filter string
}

type ManagedSecret struct {
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
	MimeType    string            `json:"mime_type"`
	CreatedAt   string            `json:"created_at"`
	Version     int               `json:"version"`
	LastUpdated string            `json:"last_updated"`
	Replicated  *bool             `json:"replicated"`
	Safe        *SafeDetails      `json:"safe"`
}

type ManagedSecretList struct {
	Secrets []ManagedSecret `json:"secrets"`
	Count   int             `json:"count"`
}

type ManagedSecretCreate struct {
	Name        string            `json:"name"`
	Value       string            `json:"value"`
	MimeType    string            `json:"mime_type,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (m ManagedSecretCreate) Validate() error {
	var errs []error
	if m.Name == "" {
		errs = append(errs, fmt.Errorf("must specify secret name"))
	}
	if m.Value == "" {
		errs = append(errs, fmt.Errorf("must specify secret value"))
	}
	if m.Value != "" && !utf8.ValidString(m.Value) {
		errs = append(errs, fmt.Errorf("secret value must be valid UTF-8"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type ManagedSecretUpdate struct {
	Value       string            `json:"value,omitempty"`
	MimeType    string            `json:"mime_type,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Validate checks constraints that apply to both partial (PATCH) and full (PUT) updates.
func (m ManagedSecretUpdate) Validate() error {
	var errs []error
	if m.Value != "" && !utf8.ValidString(m.Value) {
		errs = append(errs, fmt.Errorf("secret value must be valid UTF-8"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type ManagedSecretValue struct {
	Value    []byte
	MimeType string
}

type DynamicParams struct {
	Issuer       string         `json:"issuer"`
	IssuerType   string         `json:"issuer_type"`
	Method       string         `json:"method"`
	TTL          *int           `json:"ttl"`
	MethodParams map[string]any `json:"method_params"`
}

type DynamicSecret struct {
	Name          string            `json:"name"`
	Annotations   map[string]string `json:"annotations"`
	DynamicParams DynamicParams     `json:"dynamic_params"`
	CreatedAt     string            `json:"created_at"`
	Replicated    *bool             `json:"replicated"`
	Safe          *SafeDetails      `json:"safe"`
}

type DynamicSecretValue struct {
	Id   string         `json:"id"`
	TTL  int            `json:"ttl"`
	Data map[string]any `json:"data"`
}

type DynamicSecretList struct {
	Secrets []DynamicSecret `json:"secrets"`
	Count   int             `json:"count"`
}

type DynamicSecretCreate struct {
	Name         string            `json:"name"`
	Issuer       string            `json:"issuer"`
	TTL          int               `json:"ttl,omitempty"`
	Method       string            `json:"method"`
	MethodParams map[string]any    `json:"method_params,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func (d DynamicSecretCreate) Validate() error {
	var errs []error
	if d.Name == "" {
		errs = append(errs, fmt.Errorf("must specify secret name"))
	}
	if d.Issuer == "" {
		errs = append(errs, fmt.Errorf("must specify issuer"))
	}
	if d.Method == "" {
		errs = append(errs, fmt.Errorf("must specify method"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type DynamicSecretUpdate struct {
	Issuer       string            `json:"issuer,omitempty"`
	TTL          int               `json:"ttl,omitempty"`
	Method       string            `json:"method,omitempty"`
	MethodParams map[string]any    `json:"method_params,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// ValidateReplace checks the fields required by a full (PUT) replace; partial (PATCH) updates accept any combination of fields.
func (d DynamicSecretUpdate) ValidateReplace() error {
	var errs []error
	if d.Issuer == "" {
		errs = append(errs, fmt.Errorf("must specify issuer"))
	}
	if d.Method == "" {
		errs = append(errs, fmt.Errorf("must specify method"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// CreateManagedSecret sends a request to create a secret in a managed safe.
// The secret value is sent as JSON, so it must be valid UTF-8 and the server trims leading and trailing whitespace; use SetManagedSecretValue to store a non-UTF-8 value.
func (c *ClientV2) CreateManagedSecret(safeName string, create ManagedSecretCreate) (*ManagedSecret, error) {
	req, err := c.CreateManagedSecretRequest(safeName, create)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecret](c, req)
}

// CreateManagedSecretRequest builds an HTTP POST request to /safes/{safe_type}/{safe_name}/secrets with the given secret payload.
func (c *ClientV2) CreateManagedSecretRequest(safeName string, create ManagedSecretCreate) (*http.Request, error) {
	if err := create.Validate(); err != nil {
		return nil, err
	}

	secretsURL, err := c.secretsURL("managed", safeName)
	if err != nil {
		return nil, err
	}

	return newV2JSONRequest(http.MethodPost, secretsURL.String(), create, v2APIHeaderBeta)
}

// CreateDynamicSecret sends a request to create a secret in a dynamic safe.
func (c *ClientV2) CreateDynamicSecret(safeName string, create DynamicSecretCreate) (*DynamicSecret, error) {
	req, err := c.CreateDynamicSecretRequest(safeName, create)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecret](c, req)
}

// CreateDynamicSecretRequest builds an HTTP POST request to /safes/{safe_type}/{safe_name}/secrets with the given dynamic secret payload.
func (c *ClientV2) CreateDynamicSecretRequest(safeName string, create DynamicSecretCreate) (*http.Request, error) {
	if err := create.Validate(); err != nil {
		return nil, err
	}

	secretsURL, err := c.secretsURL("dynamic", safeName)
	if err != nil {
		return nil, err
	}

	return newV2JSONRequest(http.MethodPost, secretsURL.String(), create, v2APIHeaderBeta)
}

// ListManagedSecrets sends a request to retrieve a list of secrets in a managed safe. params can be used to control the pagination in the response.
func (c *ClientV2) ListManagedSecrets(safeName string, params ListSafeSecretParams) (*ManagedSecretList, error) {
	req, err := c.ListSecretsRequest("managed", safeName, params)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecretList](c, req)
}

// ListDynamicSecrets sends a request to retrieve a list of secrets in a dynamic safe. params can be used to control the pagination in the response.
func (c *ClientV2) ListDynamicSecrets(safeName string, params ListSafeSecretParams) (*DynamicSecretList, error) {
	req, err := c.ListSecretsRequest("dynamic", safeName, params)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecretList](c, req)
}

// ListSecretsRequest builds an HTTP GET request to /safes/{safe_type}/{safe_name}/secrets with the given request parameters.
func (c *ClientV2) ListSecretsRequest(safeType, safeName string, params ListSafeSecretParams) (*http.Request, error) {
	requestURL, err := c.secretsURL(safeType, safeName)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if params.Limit > 0 {
		query.Add("limit", strconv.Itoa(params.Limit))
	}
	if params.Offset > 0 {
		query.Add("offset", strconv.Itoa(params.Offset))
	}
	if params.Filter != "" {
		query.Add("filter", params.Filter)
	}
	requestURL.RawQuery = query.Encode()

	return newV2Request(http.MethodGet, requestURL.String(), v2APIHeaderBeta)
}

// GetManagedSecretMetadata sends a request to retrieve the metadata of a secret in a managed safe.
func (c *ClientV2) GetManagedSecretMetadata(safeName, secretName string) (*ManagedSecret, error) {
	req, err := c.GetSecretMetadataRequest("managed", safeName, secretName)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecret](c, req)
}

// GetDynamicSecretMetadata sends a request to retrieve the metadata of a secret in a dynamic safe.
func (c *ClientV2) GetDynamicSecretMetadata(safeName, secretName string) (*DynamicSecret, error) {
	req, err := c.GetSecretMetadataRequest("dynamic", safeName, secretName)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecret](c, req)
}

// GetSecretMetadataRequest builds an HTTP GET request to /safes/{safe_type}/{safe_name}/secrets/{secret_name} with the given values.
func (c *ClientV2) GetSecretMetadataRequest(safeType, safeName, secretName string) (*http.Request, error) {
	secretURL, err := c.secretURL(safeType, safeName, secretName)
	if err != nil {
		return nil, err
	}

	return newV2Request(http.MethodGet, secretURL.String(), v2APIHeaderBeta)
}

// GetManagedSecretValue sends a request to retrieve the value of a secret in a managed safe. The value is returned as a []byte and the MIME type is taken from the response Content-Type.
// If version is less than 1, the latest version of the secret is retrieved.
func (c *ClientV2) GetManagedSecretValue(safeName, secretName string, version int) (*ManagedSecretValue, error) {
	req, err := c.GetSecretValueRequest("managed", safeName, secretName, version)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	data, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	return &ManagedSecretValue{Value: data, MimeType: resp.Header.Get("Content-Type")}, nil
}

// GetDynamicSecretValue sends a request to retrieve the value of a secret in a dynamic safe.
func (c *ClientV2) GetDynamicSecretValue(safeName, secretName string) (*DynamicSecretValue, error) {
	req, err := c.GetSecretValueRequest("dynamic", safeName, secretName, 0)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecretValue](c, req)
}

// GetSecretValueRequest builds an HTTP GET request to /safes/{safe_type}/{safe_name}/secrets/{secret_name}/value with the given values.
// version is added as a request parameter in the URL if it's higher than 0.
func (c *ClientV2) GetSecretValueRequest(safeType, safeName, secretName string, version int) (*http.Request, error) {
	requestURL, err := c.secretValueURL(safeType, safeName, secretName)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	if version > 0 {
		query.Add("version", strconv.Itoa(version))
	}
	requestURL.RawQuery = query.Encode()

	return newV2Request(http.MethodGet, requestURL.String(), v2APIHeaderBeta)
}

// SetManagedSecretValue sends a request to set the value of a secret in a managed safe. The value is sent raw, so the bytes are stored exactly as given (binary, non-UTF-8 and surrounding whitespace are preserved).
// mimeType replaces the stored MIME type of the secret. To update a text value while keeping the current MIME type, use PatchManagedSecret.
// Note that the server interprets some content types (e.g. application/json and application/problem+json) as a JSON envelope instead of a raw value: unless value encodes a valid JSON object, such requests fail, and if it does, the server reads the secret value from its "value" field instead of storing the body as-is.
// To store a JSON value, use PatchManagedSecret or ReplaceManagedSecret with the desired MimeType instead.
func (c *ClientV2) SetManagedSecretValue(safeName, secretName string, value []byte, mimeType string) (*ManagedSecret, error) {
	req, err := c.SetManagedSecretValueRequest(safeName, secretName, value, mimeType)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecret](c, req)
}

// SetManagedSecretValueRequest builds an HTTP PUT request to /safes/{safe_type}/{safe_name}/secrets/{secret_name}/value with the raw value as body and mimeType as Content-Type.
func (c *ClientV2) SetManagedSecretValueRequest(safeName, secretName string, value []byte, mimeType string) (*http.Request, error) {
	var errs []error
	if len(value) == 0 {
		errs = append(errs, fmt.Errorf("must specify secret value"))
	}
	if _, _, err := mime.ParseMediaType(mimeType); err != nil {
		errs = append(errs, fmt.Errorf("invalid MIME type %q: %w", mimeType, err))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	valueURL, err := c.secretValueURL("managed", safeName, secretName)
	if err != nil {
		return nil, err
	}

	return newV2RawRequest(http.MethodPut, valueURL.String(), value, mimeType, v2APIHeaderBeta)
}

// PatchManagedSecret sends a request to partially update metadata and/or the value of a secret in a managed safe.
// This is a partial (PATCH) replacement - omitted values are left untouched.
// annotations merges with the provided map instead of replacing it, meaning that keys can only be added/updated, but not deleted.
// The metadata of the final, updated secret is returned by the server on success.
// The value is sent as JSON, so it must be valid UTF-8 and the server trims leading and trailing whitespace; use SetManagedSecretValue to store a value exactly.
func (c *ClientV2) PatchManagedSecret(safeName, secretName string, update ManagedSecretUpdate) (*ManagedSecret, error) {
	req, err := c.UpdateManagedSecretRequest(safeName, secretName, update, true)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecret](c, req)
}

// PatchDynamicSecret sends a request to partially update metadata of a secret in a dynamic safe.
// This is a partial (PATCH) replacement - omitted values are left untouched.
// annotations merges with the provided map instead of replacing it, meaning that keys can only be added/updated, but not deleted.
// The final, updated secret is returned by the server on success.
func (c *ClientV2) PatchDynamicSecret(safeName, secretName string, update DynamicSecretUpdate) (*DynamicSecret, error) {
	req, err := c.UpdateDynamicSecretRequest(safeName, secretName, update, true)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecret](c, req)
}

// ReplaceManagedSecret sends a request to fully replace metadata and/or the value of a secret in a managed safe.
// This is a full (PUT) replacement - omitted values are cleared if optional. The only exception is the secret value, which is left untouched if not provided.
// annotations are fully replaced by the provided map.
// The metadata of the final, updated secret is returned by the server on success.
// The value is sent as JSON, so it must be valid UTF-8 and the server trims leading and trailing whitespace; use SetManagedSecretValue to store a value exactly.
func (c *ClientV2) ReplaceManagedSecret(safeName, secretName string, update ManagedSecretUpdate) (*ManagedSecret, error) {
	req, err := c.UpdateManagedSecretRequest(safeName, secretName, update, false)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[ManagedSecret](c, req)
}

// ReplaceDynamicSecret sends a request to fully replace metadata of a secret in a dynamic safe.
// This is a full (PUT) replacement - omitted values are cleared if optional. annotations are fully replaced by the provided map.
// The metadata of the final, updated secret is returned by the server on success.
func (c *ClientV2) ReplaceDynamicSecret(safeName, secretName string, update DynamicSecretUpdate) (*DynamicSecret, error) {
	req, err := c.UpdateDynamicSecretRequest(safeName, secretName, update, false)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[DynamicSecret](c, req)
}

// UpdateManagedSecretRequest builds an HTTP PATCH or PUT request, depending on whether the update is partial (PATCH) or full (PUT)
// to /safes/{safe_type}/{safe_name}/secrets/{secret_name} with the given managed secret update payload.
func (c *ClientV2) UpdateManagedSecretRequest(safeName, secretName string, update ManagedSecretUpdate, partial bool) (*http.Request, error) {
	if err := update.Validate(); err != nil {
		return nil, err
	}

	secretURL, err := c.secretURL("managed", safeName, secretName)
	if err != nil {
		return nil, err
	}

	method := http.MethodPut
	if partial {
		method = http.MethodPatch
	}

	return newV2JSONRequest(method, secretURL.String(), update, v2APIHeaderBeta)
}

// UpdateDynamicSecretRequest builds an HTTP PATCH or PUT request, depending on whether the update is partial (PATCH) or full (PUT)
// to /safes/{safe_type}/{safe_name}/secrets/{secret_name} with the given dynamic secret update payload.
func (c *ClientV2) UpdateDynamicSecretRequest(safeName, secretName string, update DynamicSecretUpdate, partial bool) (*http.Request, error) {
	if !partial {
		if err := update.ValidateReplace(); err != nil {
			return nil, err
		}
	}

	secretURL, err := c.secretURL("dynamic", safeName, secretName)
	if err != nil {
		return nil, err
	}

	method := http.MethodPut
	if partial {
		method = http.MethodPatch
	}

	return newV2JSONRequest(method, secretURL.String(), update, v2APIHeaderBeta)
}

// DeleteSecret sends a request to delete a secret from a safe. nil is returned on success.
func (c *ClientV2) DeleteSecret(safeType, safeName, secretName string) error {
	req, err := c.DeleteSafeSecretRequest(safeType, safeName, secretName)
	if err != nil {
		return err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return err
	}

	return response.EmptyResponse(resp)
}

// DeleteSafeSecretRequest builds an HTTP DELETE request to /safes/{safe_type}/{safe_name}/secrets/{secret_name} with the given values.
func (c *ClientV2) DeleteSafeSecretRequest(safeType, safeName, secretName string) (*http.Request, error) {
	secretURL, err := c.secretURL(safeType, safeName, secretName)
	if err != nil {
		return nil, err
	}

	return newV2Request(http.MethodDelete, secretURL.String(), v2APIHeaderBeta)
}

// secretsURL normalizes and builds a /safes/{safe_type}/{safe_name}/secrets route.
// extra path segments are appended at the end of the base route.
func (c *ClientV2) secretsURL(safeType string, safeName string, extra ...string) (*url.URL, error) {
	if err := validateSafeTypeName(safeType, safeName); err != nil {
		return nil, err
	}

	escapedType, err := escapePathSegments("Safe Secret(s) URL", []string{safeType})
	if err != nil {
		return nil, err
	}
	escapedName, err := escapeSafeIdentifier("Safe name", safeName)
	if err != nil {
		return nil, err
	}
	escapedExtra, err := escapePathSegments("Safe Secret(s) URL", extra)
	if err != nil {
		return nil, err
	}

	segments := append([]string{"safes", escapedType[0], escapedName, "secrets"}, escapedExtra...)
	return url.Parse(makeRouterURL(c.config.ApplianceURL, segments...).String())
}

func (c *ClientV2) secretURL(safeType string, safeName string, secretName string) (*url.URL, error) {
	return c.secretsURL(safeType, safeName, secretName)
}

func (c *ClientV2) secretValueURL(safeType string, safeName string, secretName string) (*url.URL, error) {
	return c.secretsURL(safeType, safeName, secretName, "value")
}
