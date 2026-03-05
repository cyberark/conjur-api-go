package conjurapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type BatchSecretRequest struct {
	IDs []string `json:"ids"`
}

type SecretValue struct {
	ID     string `json:"id"`
	Value  string `json:"value"`
	Status int    `json:"status"`
}

type BatchSecretResponse struct {
	Secrets []SecretValue `json:"secrets"`
}

// TODO: Bump this and re-implement version checks when we have the final verison for stable V2 APIs in on-prem
const minVersion = "1.24.0"

func (c *ClientV2) BatchRetrieveSecrets(identifiers []string) (*BatchSecretResponse, error) {
	if !isConjurCloudURL(c.config.ApplianceURL) {
		return nil, fmt.Errorf(NotSupportedInConjurEnterprise, "V2 Batch Retrieve Secrets API")
	}

	req, err := c.BatchRetrieveSecretsRequest(identifiers)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	bodyData, err := response.DataResponse(resp)
	if err != nil {
		return nil, err
	}

	batchResp := BatchSecretResponse{}
	err = json.Unmarshal(bodyData, &batchResp)
	if err != nil {
		return nil, err
	}

	return &batchResp, nil
}

func (c *ClientV2) BatchRetrieveSecretsRequest(identifiers []string) (*http.Request, error) {
	validatedIDs, err := ValidateSecretIdentifiers(identifiers)
	if err != nil {
		return nil, err
	}

	batchRequest := BatchSecretRequest{IDs: validatedIDs}
	payload, err := json.Marshal(batchRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		c.batchSecretsURL(),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to create batch retrieve secrets request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(v2APIOutgoingHeaderID, v2APIHeaderBeta)

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
	if len(validIDs) > 250 {
		return nil, fmt.Errorf("Cannot request more than 250 secrets at once")
	}
	return validIDs, nil
}

func (c *ClientV2) batchSecretsURL() string {
	account := c.config.Account
	if isConjurCloudURL(c.config.ApplianceURL) {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "secrets", account, "values").String()
}
