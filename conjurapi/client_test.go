package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

func TestNewClientFromKey(t *testing.T) {
	Convey("Has authenticator of type APIKeyAuthenticator", t, func() {
		client, err := NewClientFromKey(
			Config{Account: "account", ApplianceURL: "appliance-url"},
			authn.LoginPair{"login","api-key"},
		)

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &authn.APIKeyAuthenticator{})
	})
}

func TestNewClientFromTokenFile(t *testing.T) {
	Convey("Has authenticator of type TokenFileAuthenticator", t, func() {
		client, err := NewClientFromTokenFile(Config{Account: "account", ApplianceURL: "appliance-url"}, "token-file" )

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &authn.TokenFileAuthenticator{})
	})
}

func Test_newClientWithAuthenticator(t *testing.T) {
	Convey("Returns nil and error for invalid config", t, func() {
		client, err := newClientWithAuthenticator(Config{}, nil )

		So(client, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "Must specify")
	})

	Convey("Returns client without error for valid config", t, func() {
		client, err := newClientWithAuthenticator(Config{Account: "account", ApplianceURL: "appliance-url"}, nil )

		So(err, ShouldBeNil)
		So(client, ShouldNotBeNil)
	})
}
