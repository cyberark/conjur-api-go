package conjurapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/contract"
	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

// MinVersion is the first self-hosted version supporting the V2 APIs.
const MinVersion = contract.V2MinVersion

type ClientV2 struct {
	*Client
}

// submitAndUnmarshal submits req and unmarshals the JSON response body into T.
func submitAndUnmarshal[T any](c *ClientV2, req *http.Request) (*T, error) {
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	var parsedResp T
	if err := response.JSONResponse(resp, &parsedResp); err != nil {
		return nil, err
	}
	return &parsedResp, nil
}

// submitAndReadData submits req and returns the raw response body, for routes
// whose payload the caller wants unparsed.
func submitAndReadData(c *ClientV2, req *http.Request) ([]byte, error) {
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// newV2Request builds a bodiless HTTP request for a v2 API route.
func newV2Request(method, requestURL, acceptHeader string) (*http.Request, error) {
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, acceptHeader)
	return request, nil
}

// newV2JSONRequest builds an HTTP request with a JSON-encoded body for a v2
// API route.
func newV2JSONRequest(method, requestURL string, payload any, acceptHeader string) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(method, requestURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(v2APIOutgoingHeaderID, acceptHeader)
	return request, nil
}
