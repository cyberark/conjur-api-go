package conjurapi

import (
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestNewClientFromKey(t *testing.T) {
	Convey("Has authenticator of type APIKeyAuthenticator", t, func() {
		client, err := NewClientFromKey(
			Config{Account: "account", ApplianceURL: "appliance-url"},
			authn.LoginPair{"login", "api-key"},
		)

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &authn.APIKeyAuthenticator{})
	})
}

func TestClient_GetConfig(t *testing.T) {
	Convey("Returns Client Config", t, func() {
		expectedConfig := Config{
			Account:      "some-account",
			ApplianceURL: "some-appliance-url",
			NetRCPath:    "some-netrc-path",
			SSLCert:      "some-ssl-cert",
			SSLCertPath:  "some-ssl-cert-path",
			V4:           true,
		}
		client := Client{
			config: expectedConfig,
		}

		So(client.GetConfig(), ShouldResemble, expectedConfig)
	})
}

func TestNewClientFromTokenFile(t *testing.T) {
	Convey("Has authenticator of type TokenFileAuthenticator", t, func() {
		client, err := NewClientFromTokenFile(Config{Account: "account", ApplianceURL: "appliance-url"}, "token-file")

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &authn.TokenFileAuthenticator{})
	})
}

func Test_newClientWithAuthenticator(t *testing.T) {
	Convey("Returns nil and error for invalid config", t, func() {
		client, err := newClientWithAuthenticator(Config{}, nil)

		So(client, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "Must specify")
	})

	Convey("Returns client without error for valid config", t, func() {
		client, err := newClientWithAuthenticator(Config{Account: "account", ApplianceURL: "appliance-url"}, nil)

		So(err, ShouldBeNil)
		So(client, ShouldNotBeNil)
	})
}

func Test_GetUsername(t *testing.T) {
	Convey("Returns empty string on errors", t, func() {
		client, err := NewClientFromToken(Config{
			Account:      "account",
			ApplianceURL: "http://localhost",
		}, "token-file")
		So(err, ShouldBeNil)

		So(client.GetUsername(), ShouldEqual, "")
	})

	Convey("Can return token v5 username string", t, func() {
		client, err := NewClientFromTokenFile(Config{
			Account:      "account",
			ApplianceURL: "http://localhost",
		}, "testdata/token_v5.json")
		So(err, ShouldBeNil)

		So(client.GetUsername(), ShouldEqual, "admin")
	})

	Convey("Can return token v4 username string", t, func() {
		client, err := NewClientFromTokenFile(Config{
			Account:      "account",
			ApplianceURL: "http://localhost",
		}, "testdata/token_v4.json")
		So(err, ShouldBeNil)

		So(client.GetUsername(), ShouldEqual, "admin")
	})
}
