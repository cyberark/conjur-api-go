package conjurapi

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"os/exec"
	"fmt"
	"math/rand"
)

func TestClient_RetrieveVariable(t *testing.T) {
	Convey("Given a valid configuration", t, func() {
		config := Config{
			Account:      os.Getenv("CONJUR_ACCOUNT"),
			APIKey:       os.Getenv("CONJUR_API_KEY"),
			ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
			Username:     "admin",
		}

		Convey("Existent and assigned variable is retrieved", func() {
			secret_identifier := "db/password"
			secret_value := fmt.Sprintf("secret-value-%v", rand.Intn(123456))
			cmd := fmt.Sprintf(`
secret_identifier="%s"
secret_value="%s"

response=$(curl --data "$CONJUR_API_KEY" "$CONJUR_APPLIANCE_URL/authn/$CONJUR_ACCOUNT/admin/authenticate")

token=$(echo -n $response | base64 | tr -d '\r\n')

curl -H "Authorization: Token token=\"$token\"" \
     --silent --output /dev/null \
     -X POST --data-binary @- \
     "$CONJUR_APPLIANCE_URL/policies/$CONJUR_ACCOUNT/policy/root" << EOM
- !variable $secret_identifier
EOM

curl -i -H "Authorization: Token token=\"$token\"" \
     --silent --output /dev/null \
     --data "$secret_value" \
     "$CONJUR_APPLIANCE_URL/secrets/$CONJUR_ACCOUNT/variable/$secret_identifier"

echo -n "set_db_password"
`, secret_identifier, secret_value)
			out, err := exec.Command("bash","-c", cmd).Output()
			So(err, ShouldBeNil)
			So(string(out), ShouldEqual, "set_db_password")

			conjur := NewClient(config)
			variableValue, err := conjur.RetrieveVariable(secret_identifier)

			So(err, ShouldBeNil)
			So(variableValue, ShouldEqual, secret_value)
		})

		Convey("Non-existent variable fetching returns 404", func() {
			conjur := NewClient(config)
			variableValue, err := conjur.RetrieveVariable("not-existent-secret")

			So(err, ShouldNotBeNil)
			So(variableValue, ShouldEqual, "")
			So(err.Error(), ShouldContainSubstring, "404")
		})

		Convey("When the configuration has invalid credentials", func() {
			config.Username = "invalid-user"

			Convey("Variable fetching returns 401", func() {
				conjur := NewClient(config)
				variableValue, err := conjur.RetrieveVariable("existent-or-non-existent-secret")

				So(err, ShouldNotBeNil)
				So(variableValue, ShouldEqual, "")
				So(err.Error(), ShouldContainSubstring, "401")
			})

		})
	})

}
