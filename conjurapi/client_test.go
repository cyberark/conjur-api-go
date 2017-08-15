package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewClientFromKey(t *testing.T) {
	Convey("Has authenticator of type APIKeyAuthenticator", t, func() {
		client, err := NewClientFromKey(Config{"account", "appliance-url"}, "login", "api-key" )

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &APIKeyAuthenticator{})
	})
}

func TestNewClientFromTokenFile(t *testing.T) {
	Convey("Has authenticator of type TokenFileAuthenticator", t, func() {
		client, err := NewClientFromTokenFile(Config{"account", "appliance-url"}, "token-file" )

		So(err, ShouldBeNil)
		So(client.authenticator, ShouldHaveSameTypeAs, &TokenFileAuthenticator{})
	})
}

func Test_newClientWithAuthenticator(t *testing.T) {
	Convey("Returns nil and error for invalid config", t, func() {
		client, err := newClientWithAuthenticator(Config{}, nil )

		So(client, ShouldBeNil)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "required")
	})

	Convey("Returns client without error for valid config", t, func() {
		client, err := newClientWithAuthenticator(Config{"account", "appliance-url"}, nil )

		So(err, ShouldBeNil)
		So(client, ShouldNotBeNil)
	})
}
