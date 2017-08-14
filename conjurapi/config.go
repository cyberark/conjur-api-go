package conjurapi

import (
	"fmt"
	"reflect"
	"strings"
	"os"
)

type Config struct {
	Account        string `validate:"required" env:"CONJUR_ACCOUNT"`
	APIKey         string `env:"CONJUR_AUTHN_API_KEY"`
	ApplianceURL   string `validate:"required" env:"CONJUR_APPLIANCE_URL"`
	Login          string `env:"CONJUR_AUTHN_LOGIN"`
	AuthnTokenFile string `env:"CONJUR_AUTHN_TOKEN_FILE"`
}

func (c *Config) validate() (error) {
	v := reflect.ValueOf(*c)
	errors := []string{}

	const tagName = "validate"
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		tag := f.Tag.Get(tagName)

		switch tag {
		case "required":
			val := v.Field(i).Interface()
			if val.(string) == "" {
				errors = append(errors, fmt.Sprintf("%s is required.", f.Name))
			}
		default:
		}
	}

	if len(errors) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errors, "\n"))
}

func LoadConfigFromEnv() Config {
	const tagName = "env"
	c := Config{}

	vElem := reflect.ValueOf(&c).Elem()
	vType := reflect.ValueOf(c).Type()

	for i := 0; i < vElem.NumField(); i++ {
		typeField := vType.Field(i)
		elemField := vElem.Field(i)
		tag := typeField.Tag.Get(tagName)

		switch elemField.Interface().(type) {
		case string:
			elemField.SetString(os.Getenv(tag))
		default:
			continue
		}

	}
	return c
}
