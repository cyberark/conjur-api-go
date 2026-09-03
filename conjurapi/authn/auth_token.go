package authn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	TimeFormatToken4 = "2006-01-02 15:04:05 MST"
)

// AuthnToken represents a Conjur access token.
// Sample token:
// {"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}
// https://www.conjur.org/reference/cryptography.html
type AuthnToken struct {
	bytes     []byte
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	iat       time.Time
	exp       *time.Time
}

func hasField(fields map[string]string, name string) (hasField bool) {
	_, hasField = fields[name]
	return
}

func NewToken(data []byte) (token *AuthnToken, err error) {
	fields := make(map[string]string)
	if err = json.Unmarshal(data, &fields); err != nil {
		// Only hint "base64-encoded" when the decoded bytes actually look like a Conjur token
		// (i.e. they parse as JSON with the three required token fields). Short alphanumeric
		// strings often decode successfully from base64 but are unrelated to tokens.
		if decoded, b64err := base64.StdEncoding.DecodeString(string(data)); b64err == nil {
			decodedFields := make(map[string]string)
			if json.Unmarshal(decoded, &decodedFields) == nil &&
				hasField(decodedFields, "protected") && hasField(decodedFields, "payload") && hasField(decodedFields, "signature") {
				err = fmt.Errorf("CONJUR_AUTHN_TOKEN appears to be base64-encoded; " +
					"it should be the raw JSON access token string, not a base64-encoded one")
				return
			}
		}
		err = fmt.Errorf("CONJUR_AUTHN_TOKEN is not valid JSON — " +
			"expected a Conjur access token with 'protected', 'payload', and 'signature' fields: %s", err)
		return
	}

	if hasField(fields, "protected") && hasField(fields, "payload") && hasField(fields, "signature") {
		t := &AuthnToken{}
		token = t
	} else {
		err = fmt.Errorf("CONJUR_AUTHN_TOKEN is missing required fields — " +
			"expected 'protected', 'payload', and 'signature'")
		return
	}

	err = token.FromJSON(data)

	return
}

func (t *AuthnToken) FromJSON(data []byte) (err error) {
	t.bytes = data

	err = json.Unmarshal(data, &t)
	if err != nil {
		err = fmt.Errorf("Unable to unmarshal access token: %s", err)
		return
	}

	// Example: {"sub":"admin","iat":1510753259}
	payloadFields := make(map[string]interface{})
	var payloadJSON []byte
	payloadJSON, err = base64.StdEncoding.DecodeString(t.Payload)
	if err != nil {
		err = fmt.Errorf("access token field 'payload' is not valid base64")
		return
	}
	err = json.Unmarshal(payloadJSON, &payloadFields)
	if err != nil {
		err = fmt.Errorf("Unable to unmarshal access token field 'payload': %s", err)
		return
	}

	iat_v, ok := payloadFields["iat"]
	if !ok {
		err = fmt.Errorf("access token field 'payload' does not contain 'iat'")
		return
	}
	iat_f := iat_v.(float64)
	// In the absence of exp, the token expires at iat+8 minutes
	t.iat = time.Unix(int64(iat_f), 0)

	exp_v, ok := payloadFields["exp"]
	if ok {
		exp_f := exp_v.(float64)
		exp := time.Unix(int64(exp_f), 0)
		t.exp = &exp
		if t.iat.After(*t.exp) {
			err = fmt.Errorf("access token expired before it was issued")
			return
		}
	}

	return
}

func (t *AuthnToken) Raw() []byte {
	return t.bytes
}

// Base64 returns the token's raw bytes, base64-encoded — the form used in
// the "Token token=\"...\"" Authorization header.
func (t *AuthnToken) Base64() string {
	return base64.StdEncoding.EncodeToString(t.bytes)
}

// ShouldRefresh determines if the token should be refreshed. By default tokens expire 8 minutes after issue.
func (t *AuthnToken) ShouldRefresh() bool {
	if t.exp != nil {
		// Expire when the token is 85% expired
		lifespan := t.exp.Sub(t.iat)
		duration := float32(lifespan) * 0.85
		return time.Now().After(t.iat.Add(time.Duration(duration)))
	} else {
		// Token expires 8 minutes after issue, by default
		return time.Now().After(t.iat.Add(5 * time.Minute))
	}
}
