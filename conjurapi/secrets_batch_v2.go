package conjurapi

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

type BatchSecretRequest struct {
	IDs []string `json:"ids"`
	// EncodeValues, when "base64", makes the server base64-encode every value
	// so binary (non-UTF-8) values come back instead of a per-secret 406.
	EncodeValues string `json:"encode_values,omitempty"`
}

// SecretValue is one entry in a batch response. Status is the PER-SECRET HTTP
// status (200 = value returned, 204 = authorized but empty, 403 = caller lacks
// execute, 404 = not found, 500 = server error). A partial failure — some
// secrets 403/404 while others succeed — is reported here, per secret, NOT as a
// top-level error on BatchRetrieveSecrets. Value is populated only for 200;
// Description carries the server's per-secret error detail for non-2xx entries.
type SecretValue struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	Status      int    `json:"status"`
	Description string `json:"description,omitempty"`
}

type BatchSecretResponse struct {
	Secrets []SecretValue `json:"secrets"`
}

// MaxSecretsInSingleBatch is the maximum number of identifiers the batch
// endpoint accepts in one request, mirroring the service's
// MAX_SECRETS_IN_SINGLE_BATCH.
const MaxSecretsInSingleBatch = 250

const batchEncodeBase64 = "base64"

func (c *ClientV2) BatchRetrieveSecrets(identifiers []string) (*BatchSecretResponse, error) {
	req, err := c.BatchRetrieveSecretsRequest(identifiers)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[BatchSecretResponse](c, req)
}

// BatchRetrieveSecretsSafe is BatchRetrieveSecrets, except the server
// base64-encodes every value, allowing the retrieval of binary values (which
// BatchRetrieveSecrets gets as a per-secret 406). Values are NOT base64
// encoded in the returned response. If one value can't be decoded, the whole
// call fails and returns no values.
func (c *ClientV2) BatchRetrieveSecretsSafe(identifiers []string) (*BatchSecretResponse, error) {
	req, err := c.BatchRetrieveSecretsSafeRequest(identifiers)
	if err != nil {
		return nil, err
	}

	resp, err := submitAndUnmarshal[BatchSecretResponse](c, req)
	if err != nil {
		return nil, err
	}

	for i, secret := range resp.Secrets {
		if secret.Status != http.StatusOK {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(secret.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode the value of %s: %w", secret.ID, err)
		}
		resp.Secrets[i].Value = string(decoded)
	}
	return resp, nil
}

func (c *ClientV2) BatchRetrieveSecretsRequest(identifiers []string) (*http.Request, error) {
	return c.batchRetrieveSecretsRequest(identifiers, "", v2APIHeaderBeta)
}

// BatchRetrieveSecretsSafeRequest builds the BatchRetrieveSecretsSafe request,
// which asks the server to base64-encode every value. It sends the v2 Accept
// header: the endpoint is final, and the server logs the beta one as
// deprecated there.
func (c *ClientV2) BatchRetrieveSecretsSafeRequest(identifiers []string) (*http.Request, error) {
	return c.batchRetrieveSecretsRequest(identifiers, batchEncodeBase64, v2APIHeader)
}

func (c *ClientV2) batchRetrieveSecretsRequest(identifiers []string, encodeValues string, accept string) (*http.Request, error) {
	validatedIDs, err := ValidateSecretIdentifiers(identifiers)
	if err != nil {
		return nil, err
	}

	batchRequest := BatchSecretRequest{IDs: validatedIDs, EncodeValues: encodeValues}

	req, err := newV2JSONRequest(http.MethodPost, c.batchSecretsURL(), batchRequest, accept)
	if err != nil {
		return nil, fmt.Errorf("Failed to create batch retrieve secrets request: %w", err)
	}

	return req, nil
}

func ValidateSecretIdentifiers(identifiers []string) ([]string, error) {
	// Filter out empty identifiers
	validIDs := make([]string, 0, len(identifiers))
	for _, id := range identifiers {
		if id != "" {
			validIDs = append(validIDs, id)
		}
	}
	if len(validIDs) == 0 {
		return nil, fmt.Errorf("Must specify at least one secret identifier")
	}
	if len(validIDs) > MaxSecretsInSingleBatch {
		return nil, fmt.Errorf(
			"Cannot request more than %d secrets at once (got %d)",
			MaxSecretsInSingleBatch, len(validIDs),
		)
	}
	return validIDs, nil
}

func (c *ClientV2) batchSecretsURL() string {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "secrets", account, "values").String()
}
