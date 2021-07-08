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
- !variable db-password-2
- !variable password

- !permit
  role: !user alice
  privilege: [ execute ]
  resource: !variable db-password

- !policy
  id: prod
  body:
  - !variable cluster-admin
  - !variable cluster-admin-password

  - !policy
    id: database
    body:
    - !variable username
    - !variable password
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

	if os.Getenv("TEST_VERSION") != "oss" {
		Convey("V4", t, func() {
			conjur, err := v4Setup()
			So(err, ShouldBeNil)

			Convey("Check an allowed permission", checkAllowed(conjur, "cucumber:variable:existent-variable-with-defined-value"))

			Convey("Check a permission on a non-existent resource", checkNonExisting(conjur, "cucumber:variable:foobar"))
		})
	}
}

func TestClient_Resources(t *testing.T) {
	listResources := func(conjur *Client, filter *ResourceFilter, expected int) func() {
		return func() {
			resources, err := conjur.Resources(filter)
			So(err, ShouldBeNil)
			So(len(resources), ShouldEqual, expected)
		}
	}

	Convey("V5", t, func() {
		conjur, err := v5Setup()
		So(err, ShouldBeNil)

		Convey("Lists all resources", listResources(conjur, nil, 11))
		Convey("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}, 7))
		Convey("Lists resources that start with db", listResources(conjur, &ResourceFilter{Search: "db"}, 2))
		Convey("Lists variables that start with prod/database", listResources(conjur, &ResourceFilter{Search: "prod/database", Kind: "variable"}, 2))
		Convey("Lists variables that start with prod", listResources(conjur, &ResourceFilter{Search: "prod", Kind: "variable"}, 4))
		Convey("Lists resources and limit result to 1", listResources(conjur, &ResourceFilter{Limit: 1}, 1))
		Convey("Lists resources after the first", listResources(conjur, &ResourceFilter{Offset: 1}, 10))
	})

	if os.Getenv("TEST_VERSION") != "oss" {
		Convey("V4", t, func() {
			conjur, err := v4Setup()
			So(err, ShouldBeNil)

			Convey("Lists all resources", listResources(conjur, nil, 35))
			Convey("Lists resources by kind", listResources(conjur, &ResourceFilter{Kind: "variable"}, 16))
			Convey("Lists resources that start with db", listResources(conjur, &ResourceFilter{Search: "db"}, 1))
			Convey("Lists variables that start with prod", listResources(conjur, &ResourceFilter{Search: "authn-tv/api-key", Kind: "variable"}, 1))
			Convey("Lists resources and limit result to 1", listResources(conjur, &ResourceFilter{Limit: 1}, 1))
			Convey("Lists resources after the first", listResources(conjur, &ResourceFilter{Offset: 1}, 10))
		})
	}
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

	if os.Getenv("TEST_VERSION") != "oss" {
		Convey("V4", t, func() {
			conjur, err := v4Setup()
			So(err, ShouldBeNil)

			// v4 router doesn't support it yet.
			SkipConvey("Shows a resource", showResource(conjur, "cucumber:variable:existent-variable-with-defined-value"))
		})
	}
}
