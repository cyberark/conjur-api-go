package authn

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestTokenV5_Parse(t *testing.T) {

	token_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_with_exp_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OSwiZXhwIjoxNTEwNzUzMzU5fQo=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"WIiOiJhZG1","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`
	token_mangled_2_s := `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"Zm9vYmFyCg==","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

	Convey("Token type V5 is detected", t, func() {
		token, err := NewToken([]byte(token_s))

		So(err, ShouldBeNil)
		So(reflect.TypeOf(token).String(), ShouldEqual, "*authn.AuthnToken5")
		So(token.Raw(), ShouldBeNil)
	})

	Convey("Token fields are parsed as expected", t, func() {
		token, err := NewToken([]byte(token_s))

		err = token.FromJSON([]byte(token_s))
		So(err, ShouldBeNil)

		So(string(token.Raw()), ShouldEqual, token_s)

		token_v5 := token.(*AuthnToken5)
		So(token_v5.iat.String(), ShouldEqual, time.Unix(1510753259, 0).String())
		So(token_v5.exp, ShouldBeNil)

		So(token.ShouldRefresh(), ShouldEqual, true)
	})

	Convey("Token exp is supported", t, func() {
		token, err := NewToken([]byte(token_with_exp_s))

		err = token.FromJSON([]byte(token_with_exp_s))
		So(err, ShouldBeNil)

		token_v5 := token.(*AuthnToken5)
		So(token_v5.iat.String(), ShouldEqual, time.Unix(1510753259, 0).String())
		So(token_v5.exp.String(), ShouldEqual, time.Unix(1510753359, 0).String())

		So(token.ShouldRefresh(), ShouldEqual, true)
	})

	Convey("Malformed base64 in token is reported", t, func() {
		token, err := NewToken([]byte(token_mangled_s))

		err = token.FromJSON([]byte(token_mangled_s))
		So(err.Error(), ShouldEqual, "v5 access token field 'payload' is not valid base64")
	})

	Convey("Malformed JSON in token is reported", t, func() {
		token, err := NewToken([]byte(token_mangled_2_s))

		err = token.FromJSON([]byte(token_mangled_2_s))
		So(err.Error(), ShouldEqual, "Unable to unmarshal v5 access token field 'payload' : invalid character 'o' in literal false (expecting 'a')")
	})
}

func TestTokenV4_Parse(t *testing.T) {
	expired_token_bytes := []byte(`{"data":"admin","timestamp":"2018-04-06 03:10:08 UTC","signature":"QxTMoWWYXbgMo_JuX4KHQuiPwPRe8fpIlnZMhlvHalyhJHK0RbkqOyw28ImLwClBaTPjx6KU7KmqYLi9pMszHQZhQ7A2fLm1v-x0XzZGrDOt6gd0fTEZ0CJl7VVxVBZWLrJ83r8tY-sdjKysrE1fyDXyMU_vDtgJVi9y72qddkH-Pl16Pd4PJceEEybfWylIs1Z5V5qn-ocWX18D-i9pB67Usz3m-wKa43TptiDYLGU1-Y_EXyilv_uNGouqwYa0IueK5yJxO1Rcyb2aCBG0i-0Vl7qYrT0zIwDqmxLAwbqOtrtfHngFOCqsW04jJLPOruR5FwMlGw90GT1lZH_3GCm6QK8p15IWfVS9UOky8Y4l-1vfh-d15BZPGemUbu0j","key":"86ffd9d612ad06fe978b559fbeba4ca2"}`)
	var expired_token *AuthnToken4

	Convey("Token type V4 is detected", t, func() {
		token, err := NewToken(expired_token_bytes)
		err = token.FromJSON(expired_token_bytes)

		So(err, ShouldBeNil)
		So(reflect.TypeOf(token).String(), ShouldEqual, "*authn.AuthnToken4")
		So(token.Raw(), ShouldNotBeNil)

		expired_token, _ = token.(*AuthnToken4)
	})

	Convey("Token timestamp is non-zero", t, func() {
		So(expired_token.Timestamp.IsZero(), ShouldEqual, false)
	})

	Convey("Expired token should be refreshed", t, func() {
		So(expired_token.ShouldRefresh(), ShouldEqual, true)
	})

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := http.Client{Transport: tr}

	authUrl := fmt.Sprintf("%s/authn/users/%s/authenticate",
		os.Getenv("CONJUR_V4_APPLIANCE_URL"),
		url.PathEscape(os.Getenv("CONJUR_V4_AUTHN_LOGIN")))

	req, err := http.NewRequest("POST",
		authUrl,
		bytes.NewBuffer([]byte(os.Getenv("CONJUR_V4_AUTHN_API_KEY"))))

	if err != nil {
		log.Printf("Failed creating request to authenticate: %s\n", err)
		log.Println("Cannot continue.")
		return
	}

	req.Header.Set("Accept", "*/*")
	res, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Failed creating request to authenticate: %s\n", err)
		log.Println("Cannot continue.")
		return
	}

	if res.StatusCode != http.StatusOK {
		log.Printf("Received %d response when authenticating.\n", res.StatusCode)
		log.Println("Cannot continue.")
	}

	new_token_bytes, _ := ioutil.ReadAll(res.Body)

	Convey("New token can be parsed and fields are valid", t, func() {
		token, err := NewToken([]byte(new_token_bytes))
		err = token.FromJSON(new_token_bytes)
		token4, _ := token.(*AuthnToken4)

		So(err, ShouldBeNil)
		So(reflect.TypeOf(token).String(), ShouldEqual, "*authn.AuthnToken4")
		So(token4.Timestamp.IsZero(), ShouldEqual, false)
		So(token.ShouldRefresh(), ShouldEqual, false)
		So(token.Raw(), ShouldNotBeNil)
	})
}
