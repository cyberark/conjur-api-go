package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	. "github.com/smartystreets/goconvey/convey"
)

func v5Setup() (*Client, error) {
	config := &Config{}
	config.mergeEnv()

	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	login := os.Getenv("CONJUR_AUTHN_LOGIN")

	policy := fmt.Sprintf(`
- !user alice

- !variable db-password

- !permit
  role: !user alice
  privilege: [ execute ]
  resource: !variable db-password
`)

	conjur, err := NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})

	if err == nil {
		conjur.LoadPolicy(
			PolicyModePut,
			"root",
			strings.NewReader(policy),
		)
	}

	return conjur, err
}

func v4Setup() (*Client, error) {
	config := &Config{
		ApplianceURL: os.Getenv("CONJUR_V4_APPLIANCE_URL"),
		SSLCert:      os.Getenv("CONJUR_V4_SSL_CERTIFICATE"),
		Account:      os.Getenv("CONJUR_V4_ACCOUNT"),
		V4:           true,
	}

	login := os.Getenv("CONJUR_V4_AUTHN_LOGIN")
	apiKey := os.Getenv("CONJUR_V4_AUTHN_API_KEY")

	return NewClientFromKey(*config, authn.LoginPair{Login: login, APIKey: apiKey})
}

func TestClient_CheckPermission(t *testing.T) {
	checkAllowed := func(conjur *Client, id string) func() {
		return func() {
			allowed, err := conjur.CheckPermission(id, "execute")

			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		}
	}

	checkNonExisting := func(conjur *Client, id string) func() {
		return func() {
			allowed, err := conjur.CheckPermission(id, "execute")

			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		}
	}

	Convey("V5", t, func() {
		conjur, err := v5Setup()
		So(err, ShouldBeNil)

		Convey("Check an allowed permission", checkAllowed(conjur, "cucumber:variable:db-password"))

		Convey("Check a permission on a non-existent resource", checkNonExisting(conjur, "cucumber:variable:foobar"))
	})
	Convey("V4", t, func() {
		conjur, err := v4Setup()
		So(err, ShouldBeNil)

		Convey("Check an allowed permission", checkAllowed(conjur, "cucumber:variable:existent-variable-with-defined-value"))

		Convey("Check a permission on a non-existent resource", checkNonExisting(conjur, "cucumber:variable:foobar"))
	})
}

func TestClient_Resources(t *testing.T) {
	listResources := func(conjur *Client, filter *ResourceFilter) func() {
		return func() {
			resources, err := conjur.Resources(filter)
			So(err, ShouldBeNil)
			So(len(resources), ShouldBeGreaterThan, 0)
		}
	}

	Convey("V5", t, func() {
		conjur, err := v5Setup()
		So(err, ShouldBeNil)

		Convey("Lists all resources", listResources(conjur, nil))
		Convey("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}))
	})

	Convey("V4", t, func() {
		conjur, err := v4Setup()
		So(err, ShouldBeNil)

		// v4 router doesn't support it yet.
		SkipConvey("Lists resources", listResources(conjur, nil))
	})
}

func TestClient_Resource(t *testing.T) {
	showResource := func(conjur *Client, id string) func() {
		return func() {
			_, err := conjur.Resource(id)
			So(err, ShouldBeNil)
		}
	}

	Convey("V5", t, func() {
		conjur, err := v5Setup()
		So(err, ShouldBeNil)

		Convey("Shows a resource", showResource(conjur, "cucumber:variable:db-password"))
	})

	Convey("V4", t, func() {
		conjur, err := v4Setup()
		So(err, ShouldBeNil)

		// v4 router doesn't support it yet.
		SkipConvey("Shows a resource", showResource(conjur, "cucumber:variable:existent-variable-with-defined-value"))
	})
}
