package swafake

import (
	"encoding/json"
	"io"
	"net/http"
)

// contentTypeJSON is what the fake responds with. The SDK sends a versioned
// Accept header, but the real service replies with plain application/json, so
// the fake does too.
const contentTypeJSON = "application/json"

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// writeError writes an error response in standard {code, message} shape.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

// decodeBody reads and unmarshals the JSON request body into v. It returns
// false (after writing a 400) when the body is not valid JSON.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "unable to read request body")
		return false
	}
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

// baseURL returns the fake's externally-visible base URL for a request.
func baseURL(r *http.Request) string {
	return "http://" + r.Host
}

// paginate slices items by the limit/offset query parameters, returning the
// page and the total count.
func paginate[T any](items []T, limit, offset *int32) ([]T, int64) {
	total := int64(len(items))
	start := 0
	if offset != nil && *offset > 0 {
		start = int(*offset)
	}
	if start > len(items) {
		start = len(items)
	}
	end := len(items)
	if limit != nil && *limit > 0 && start+int(*limit) < end {
		end = start + int(*limit)
	}
	return items[start:end], total
}
