package conjurapi

import (
	"fmt"
	"net/http"
)

type BatchSecretRequest struct {
	IDs []string `json:"ids"`
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

func (c *ClientV2) BatchRetrieveSecrets(identifiers []string) (*BatchSecretResponse, error) {
	if err := c.requireSaaS(batchRetrieveSecretsAPIName); err != nil {
		return nil, err
	}

	req, err := c.BatchRetrieveSecretsRequest(identifiers)
	if err != nil {
		return nil, err
	}

	return submitAndUnmarshal[BatchSecretResponse](c, req)
}

func (c *ClientV2) BatchRetrieveSecretsRequest(identifiers []string) (*http.Request, error) {
	validatedIDs, err := ValidateSecretIdentifiers(identifiers)
	if err != nil {
		return nil, err
	}

	batchRequest := BatchSecretRequest{IDs: validatedIDs}

	req, err := newV2JSONRequest(http.MethodPost, c.batchSecretsURL(), batchRequest, v2APIHeaderBeta)
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
