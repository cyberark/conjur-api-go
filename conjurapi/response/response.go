package response

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	responseText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return responseText, err
}

func logResponse(resp *http.Response) {
	req := resp.Request
	redactedHeaders := redactHeaders(req.Header)
	logging.ApiLog.Debugf("%d %s %s %+v", resp.StatusCode, req.Method, req.URL, redactedHeaders)
}

const redactedString = "[REDACTED]"

// redactHeaders purges Authorization headers, and returns a function to restore them.
func redactHeaders(headers http.Header) http.Header {
	origAuthz := headers.Get("Authorization")
	if origAuthz != "" {
		newHeaders := headers.Clone()
		newHeaders.Set("Authorization", redactedString)
		return newHeaders
	}
	return headers
}

// DataResponse checks the HTTP status of the response. If it's less than
// 300, it returns the response body as a byte array. Otherwise it returns
// a NewConjurError.
func DataResponse(resp *http.Response) ([]byte, error) {
	logResponse(resp)
	if resp.StatusCode < 300 {
		return readBody(resp)
	}
	return nil, NewConjurError(resp)
}

// SecretDataResponse checks the HTTP status of the response. If it's less than
// 300, it returns the response body as a stream. Otherwise it returns
// a NewConjurError.
func SecretDataResponse(resp *http.Response) (io.ReadCloser, error) {
	logResponse(resp)
	if resp.StatusCode < 300 {
		return resp.Body, nil
	}
	return nil, NewConjurError(resp)
}

// JSONResponse checks the HTTP status of the response. If it's less than
// 300, it returns the response body as JSON. Otherwise it returns
// a NewConjurError.
func JSONResponse(resp *http.Response, obj interface{}) error {
	logResponse(resp)
	if resp.StatusCode < 300 {
		body, err := readBody(resp)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, obj)
	}
	return NewConjurError(resp)
}

// JSONResponseWithAllowedStatusCodes checks the HTTP status of the response. If it's less than
// 300 or equal to one of the provided values, it returns the response body as JSON. Otherwise it
// returns a NewConjurError.
func JSONResponseWithAllowedStatusCodes(resp *http.Response, obj interface{}, allowedStatusCodes []int) error {
	logResponse(resp)
	if resp.StatusCode < 300 || contains(allowedStatusCodes, resp.StatusCode) {
		body, err := readBody(resp)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, obj)
	}
	return NewConjurError(resp)
}

func contains(allowedStatusCodes []int, i int) bool {
	for _, v := range allowedStatusCodes {
		if v == i {
			return true
		}
	}
	return false
}

// EmptyResponse checks the HTTP status of the response. If it's less than
// 300, it returns without an error. Otherwise it returns
// a NewConjurError.
func EmptyResponse(resp *http.Response) error {
	logResponse(resp)
	if resp.StatusCode < 300 {
		return nil
	}
	return NewConjurError(resp)
}

// DryRunPolicyJSONResponse checks the HTTP status of the response. If it's less than
// 300 or equal to 422, it returns the response body as JSON. Otherwise it
// returns a NewConjurError.
func DryRunPolicyJSONResponse(resp *http.Response, obj interface{}) error {
	return JSONResponseWithAllowedStatusCodes(resp, obj, []int{422})
}
