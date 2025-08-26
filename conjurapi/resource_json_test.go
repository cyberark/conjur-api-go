package conjurapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	jsonA = `
	{
		"identifier": "demo:user:alice",
		"id": "alice",
		"type": "user",
		"owner": "demo:user:admin",
		"policy": "demo:user:example",
		"annotations": {"key": "value"},
		"permissions": {"execute": ["demo:variable:example/alpha/secret01","demo:variable"]},
		"members": ["demo:user:admin"],"memberships": ["demo:group:secret-users"],
		"restricted_to": ["127.0.0.1"]
	}`

	jsonB = `
	{
		"identifier": "conjur:variable:example/alpha/secret01",
		"id": "example/alpha/secret01",
		"type": "variable",
		"owner": "conjur:policy:example/alpha",
		"policy": "conjur:policy:root",
		"permitted": {
			"execute": [
				"conjur:group:example/alpha/secret-users"
			],
			"read": [
				"conjur:group:example/alpha/secret-users"
			]
		},
		"annotations": {
			"key": "value"
		}
	}`
)

var (
	resourceA = Resource{
		Identifier:  "demo:user:alice",
		Id:          "alice",
		Type:        "user",
		Owner:       "demo:user:admin",
		Policy:      "demo:user:example",
		Annotations: map[string]string{"key": "value"},
		Permissions: &map[string][]string{
			"execute": {
				"demo:variable:example/alpha/secret01",
				"demo:variable",
			},
		},
		Members:      &[]string{"demo:user:admin"},
		Memberships:  &[]string{"demo:group:secret-users"},
		RestrictedTo: &[]string{"127.0.0.1"},
	}

	resourceB = Resource{
		Identifier: "conjur:variable:example/alpha/secret01",
		Id:         "example/alpha/secret01",
		Type:       "variable",
		Owner:      "conjur:policy:example/alpha",
		Policy:     "conjur:policy:root",
		Permitted: &map[string][]string{
			"execute": []string{"conjur:group:example/alpha/secret-users"},
			"read":    []string{"conjur:group:example/alpha/secret-users"},
		},
		Annotations: map[string]string{"key": "value"},
	}
	resourceList = []Resource{resourceA, resourceB}
)

func TestResource_UnmarshalJSON(t *testing.T) {
	var unmarshalledResource Resource
	tests := []struct {
		name string
		arg  string
		want Resource
	}{
		{
			name: "Unmarshal Role",
			arg:  jsonA,
			want: resourceA,
		},
		{
			name: "Unmarshal Resource",
			arg:  jsonB,
			want: resourceB,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json.Unmarshal([]byte(tt.arg), &unmarshalledResource)
			assert.Equal(t, &tt.want, &unmarshalledResource)
			unmarshalledResource = Resource{}
		})
	}
}

func TestResource_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		arg  Resource
		want string
	}{
		{
			name: "Marshal Role",
			arg:  resourceA,
			want: jsonA,
		},
		{
			name: "Marshal Resource",
			arg:  resourceB,
			want: jsonB,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.arg)
			assert.Nil(t, err)
			assert.JSONEq(t, tt.want, string(result))
		})
	}
}

func TestResources_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		arg  []Resource
		want string
	}{
		{
			name: "Marshal List",
			arg:  resourceList,
			want: fmt.Sprintf("[%s,%s]", jsonA, jsonB),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.arg)
			assert.Nil(t, err)
			assert.JSONEq(t, tt.want, string(result))
		})
	}
}
func TestResources_UnmarshalJSON(t *testing.T) {
	var unmarshalledResources []Resource
	tests := []struct {
		name string
		arg  string
		want []Resource
	}{
		{
			name: "Unmarshal List",
			arg:  fmt.Sprintf("[%s,%s]", jsonA, jsonB),
			want: resourceList,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json.Unmarshal([]byte(tt.arg), &unmarshalledResources)
			assert.Equal(t, &tt.want, &unmarshalledResources)
		})
	}
}
