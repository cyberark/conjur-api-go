package authn

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken_Parse(t *testing.T) {

	token_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_with_exp_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OSwiZXhwIjoxNTEwNzUzMzU5fQo=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"WIiOiJhZG1","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_2_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"Zm9vYmFyCg==","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

	t.Run("Token is parsed successfully", func(t *testing.T) {
		token, err := NewToken([]byte(token_s))

		assert.NoError(t, err)
		assert.Equal(t, "*authn.AuthnToken", reflect.TypeOf(token).String())
		assert.NotNil(t, token.Raw())
	})

	t.Run("Token fields are parsed as expected", func(t *testing.T) {
		token, err := NewToken([]byte(token_s))
		assert.NoError(t, err)

		assert.Equal(t, token_s, string(token.Raw()))

		assert.Equal(t, time.Unix(1510753259, 0).String(), token.iat.String())
		assert.Nil(t, token.exp)

		assert.True(t, token.ShouldRefresh())
	})

	t.Run("Token exp is supported", func(t *testing.T) {
		token, err := NewToken([]byte(token_with_exp_s))
		assert.NoError(t, err)

		assert.Equal(t, time.Unix(1510753259, 0).String(), token.iat.String())
		assert.Equal(t, time.Unix(1510753359, 0).String(), token.exp.String())

		assert.True(t, token.ShouldRefresh())
	})

	t.Run("Malformed base64 in token is reported", func(t *testing.T) {
		_, err := NewToken([]byte(token_mangled_s))
		assert.Equal(t, "access token field 'payload' is not valid base64", err.Error())
	})

	t.Run("Malformed JSON in token is reported", func(t *testing.T) {
		_, err := NewToken([]byte(token_mangled_2_s))
		assert.Equal(t, "Unable to unmarshal access token field 'payload': invalid character 'o' in literal false (expecting 'a')", err.Error())
	})

	t.Run("Invalid JSON in token is reported", func(t *testing.T) {
		token, err := NewToken([]byte("invalid json"))
		assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN is not valid JSON")
		assert.ErrorContains(t, err, "'protected', 'payload', and 'signature'")
		assert.Nil(t, token)
	})

	t.Run("Base64-encoded token is identified", func(t *testing.T) {
		// Simulate a caller who accidentally base64-encoded the JSON token.
		// The decoded payload must resemble a real token (with the 3 required fields)
		// for the hint to fire.
		tokenJSON := `{"protected":"xxx","payload":"yyy","signature":"zzz"}`
		b64Token := base64.StdEncoding.EncodeToString([]byte(tokenJSON))
		token, err := NewToken([]byte(b64Token))
		assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN appears to be base64-encoded")
		assert.Nil(t, token)
	})

	t.Run("Non-token base64 string returns generic JSON error", func(t *testing.T) {
		// A string that happens to be valid base64 but whose decoded content is not
		// a Conjur token should get the generic "not valid JSON" error, not the
		// misleading "appears to be base64-encoded" hint.
		b64Token := base64.StdEncoding.EncodeToString([]byte(`{"foo":"bar"}`))
		token, err := NewToken([]byte(b64Token))
		assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN is not valid JSON")
		assert.Nil(t, token)
	})

	t.Run("Token without correct fields", func(t *testing.T) {
		token, err := NewToken([]byte(`{"foo":"bar"}`))
		assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN is missing required fields")
		assert.ErrorContains(t, err, "'protected', 'payload', and 'signature'")
		assert.Nil(t, token)
	})

	t.Run("Token without iat", func(t *testing.T) {
		token_without_iat := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiJ9Cg==","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
		_, err := NewToken([]byte(token_without_iat))
		assert.EqualError(t, err, "access token field 'payload' does not contain 'iat'")
	})

	t.Run("Token expired before issued", func(t *testing.T) {
		token_exp_before_issued := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzM1OSwiZXhwIjoxNTEwNzUzMjU5fQo=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
		_, err := NewToken([]byte(token_exp_before_issued))
		assert.EqualError(t, err, "access token expired before it was issued")
	})

	t.Run("FromJSON returns error when provided invalid JSON", func(t *testing.T) {
		token := &AuthnToken{}
		err := token.FromJSON([]byte("invalid json"))
		assert.EqualError(t, err, "Unable to unmarshal access token: invalid character 'i' looking for beginning of value")
	})
}

func TestNewTokenFromSource_NamesSource(t *testing.T) {
	_, err := NewTokenFromSource([]byte("invalid json"), "CONJUR_AUTHN_TOKEN_FILE")
	assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN_FILE is not valid JSON")
	_, err = NewTokenFromSource([]byte(`{"protected":"x"}`), "CONJUR_AUTHN_TOKEN_FILE")
	assert.ErrorContains(t, err, "CONJUR_AUTHN_TOKEN_FILE is missing required fields")
}
