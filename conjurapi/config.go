package conjurapi

import (
	"fmt"
	"reflect"
	"strings"
)

type Config struct {
	Account        string `validate:"required"`
	APIKey         string
	ApplianceURL   string `validate:"required"`
	Username       string
	AuthnTokenFile string
}

const tagName = "validate"

func (c Config) IsValid() (bool, error) {
	v := reflect.ValueOf(c)
	errors := []string{}

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
		return true, nil
	}
	return false, fmt.Errorf("%s", strings.Join(errors, "\n"))
}

