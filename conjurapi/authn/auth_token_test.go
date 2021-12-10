package authn

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenV5_Parse(t *testing.T) {

	token_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_with_exp_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OSwiZXhwIjoxNTEwNzUzMzU5fQo=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"WIiOiJhZG1","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_2_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"Zm9vYmFyCg==","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

	t.Run("Token type V5 is detected", func(t *testing.T) {
		token, err := NewToken([]byte(token_s))

		assert.NoError(t, err)
		assert.Equal(t, "*authn.AuthnToken5", reflect.TypeOf(token).String())
		assert.NotNil(t, token.Raw())
	})

	t.Run("Token fields are parsed as expected", func(t *testing.T) {
		token, err := NewToken([]byte(token_s))
		assert.NoError(t, err)

		assert.Equal(t, token_s, string(token.Raw()))

		token_v5 := token.(*AuthnToken5)
		assert.Equal(t, time.Unix(1510753259, 0).String(), token_v5.iat.String())
		assert.Nil(t, token_v5.exp)

		assert.True(t, token.ShouldRefresh())
	})

	t.Run("Token exp is supported", func(t *testing.T) {
		token, err := NewToken([]byte(token_with_exp_s))
		assert.NoError(t, err)

		token_v5 := token.(*AuthnToken5)
		assert.Equal(t, time.Unix(1510753259, 0).String(), token_v5.iat.String())
		assert.Equal(t, time.Unix(1510753359, 0).String(), token_v5.exp.String())

		assert.True(t, token.ShouldRefresh())
	})

	t.Run("Malformed base64 in token is reported", func(t *testing.T) {
		_, err := NewToken([]byte(token_mangled_s))
		assert.Equal(t, "v5 access token field 'payload' is not valid base64", err.Error())
	})

	t.Run("Malformed JSON in token is reported", func(t *testing.T) {
		_, err := NewToken([]byte(token_mangled_2_s))
		assert.Equal(t, "Unable to unmarshal v5 access token field 'payload' : invalid character 'o' in literal false (expecting 'a')", err.Error())
	})
}

func TestTokenV4_Parse(t *testing.T) {
	expired_token_bytes := []byte(`{"data":"admin","timestamp":"2018-04-06 03:10:08 UTC","signature":"QxTMoWWYXbgMo_JuX4KHQuiPwPRe8fpIlnZMhlvHalyhJHK0RbkqOyw28ImLwClBaTPjx6KU7KmqYLi9pMszHQZhQ7A2fLm1v-x0XzZGrDOt6gd0fTEZ0CJl7VVxVBZWLrJ83r8tY-sdjKysrE1fyDXyMU_vDtgJVi9y72qddkH-Pl16Pd4PJceEEybfWylIs1Z5V5qn-ocWX18D-i9pB67Usz3m-wKa43TptiDYLGU1-Y_EXyilv_uNGouqwYa0IueK5yJxO1Rcyb2aCBG0i-0Vl7qYrT0zIwDqmxLAwbqOtrtfHngFOCqsW04jJLPOruR5FwMlGw90GT1lZH_3GCm6QK8p15IWfVS9UOky8Y4l-1vfh-d15BZPGemUbu0j","key":"86ffd9d612ad06fe978b559fbeba4ca2"}`)

	nextYear := time.Now().Year() + 1
	new_token_bytes := []byte(fmt.Sprintf(`{"data":"admin","timestamp":"%v-04-06 03:10:08 UTC","signature":"QxTMoWWYXbgMo_JuX4KHQuiPwPRe8fpIlnZMhlvHalyhJHK0RbkqOyw28ImLwClBaTPjx6KU7KmqYLi9pMszHQZhQ7A2fLm1v-x0XzZGrDOt6gd0fTEZ0CJl7VVxVBZWLrJ83r8tY-sdjKysrE1fyDXyMU_vDtgJVi9y72qddkH-Pl16Pd4PJceEEybfWylIs1Z5V5qn-ocWX18D-i9pB67Usz3m-wKa43TptiDYLGU1-Y_EXyilv_uNGouqwYa0IueK5yJxO1Rcyb2aCBG0i-0Vl7qYrT0zIwDqmxLAwbqOtrtfHngFOCqsW04jJLPOruR5FwMlGw90GT1lZH_3GCm6QK8p15IWfVS9UOky8Y4l-1vfh-d15BZPGemUbu0j","key":"86ffd9d612ad06fe978b559fbeba4ca2"}`, nextYear))

	var expired_token *AuthnToken4

	t.Run("Token type V4 is detected", func(t *testing.T) {
		token, err := NewToken(expired_token_bytes)

		assert.NoError(t, err)
		assert.Equal(t, "*authn.AuthnToken4", reflect.TypeOf(token).String())
		assert.NotNil(t, token.Raw())

		expired_token, _ = token.(*AuthnToken4)
	})

	t.Run("Token timestamp is non-zero", func(t *testing.T) {
		assert.False(t, expired_token.Timestamp.IsZero())
	})

	t.Run("Expired token should be refreshed", func(t *testing.T) {
		assert.True(t, expired_token.ShouldRefresh())
	})

	t.Run("New token can be parsed and fields are valid", func(t *testing.T) {
		token, err := NewToken([]byte(new_token_bytes))
		token4, _ := token.(*AuthnToken4)

		assert.NoError(t, err)
		assert.Equal(t, "*authn.AuthnToken4", reflect.TypeOf(token).String())
		assert.False(t, token4.Timestamp.IsZero())
		assert.False(t, token4.ShouldRefresh())
		assert.NotNil(t, token4.Raw())
	})
}
