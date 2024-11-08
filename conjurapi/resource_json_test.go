package conjurapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	jsonA = `
	{
		"identifier": "cucumber:group:example/alpha/secret-users",
		"id": "example/alpha/secret-users",
		"type": "group",
		"owner": "cucumber:policy:example/alpha",
		"policy": "cucumber:policy:root",
		"permissions": {
			"execute": [
				"cucumber:variable:example/alpha/secret01",
				"cucumber:variable:example/alpha/secret02"
			],
			"read": [
				"cucumber:variable:example/alpha/secret01",
				"cucumber:variable:example/alpha/secret02"
			]
		},
		"annotations": {
			"key": "value"
		},
		"members": [
			"cucumber:policy:example/alpha",
			"cucumber:user:annie@example"
		],
		"memberships": [],
		"restricted_to": []
	}`
	jsonB = `
	{
		"identifier": "cucumber:variable:example/alpha/secret01",
		"id": "example/alpha/secret01",
		"type": "variable",
		"owner": "cucumber:policy:example/alpha",
		"policy": "cucumber:policy:root",
		"permitted": {
			"execute": [
				"cucumber:group:example/alpha/secret-users"
			],
			"read": [
				"cucumber:group:example/alpha/secret-users"
			]
		},
		"annotations": {
			"key": "value"
		}
	}`
)

var (
	resourceA = Resource{
		Identifier: "cucumber:group:example/alpha/secret-users",
		Id:         "example/alpha/secret-users",
		Type:       "group",
		Owner:      "cucumber:policy:example/alpha",
		Policy:     "cucumber:policy:root",
		Permissions: *map[string][]string{
			"execute": []string{"cucumber:variable:example/alpha/secret01", "cucumber:variable:example/alpha/secret02"},
			"read":    []string{"cucumber:variable:example/alpha/secret01", "cucumber:variable:example/alpha/secret02"},
		},
		Annotations:   map[string]string{"key": "value"},
		Members:       *[]string{"cucumber:policy:example/alpha", "cucumber:user:annie@example"},
		Memberships:   *[]string{},
		Restricted_To: *[]string{},
	}

	resourceB = Resource{
		Identifier: "cucumber:variable:example/alpha/secret01",
		Id:         "example/alpha/secret01",
		Type:       "variable",
		Owner:      "cucumber:policy:example/alpha",
		Policy:     "cucumber:policy:root",
		Permitted: *map[string][]string{
			"execute": []string{"cucumber:group:example/alpha/secret-users"},
			"read":    []string{"cucumber:group:example/alpha/secret-users"},
		},
		Annotations: map[string]string{"key": "value"},
	}
	resourceList = Resources{resourceA, resourceB}
)

func TestResource_UnmarshalJSON(t *testing.T) {
	var unmarshalled_resource Resource
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
			json.Unmarshal([]byte(tt.arg), &unmarshalled_resource)
			assert.Equal(t, &tt.want, &unmarshalled_resource)
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
		arg  Resources
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
	var unmarshalled_resources Resources
	tests := []struct {
		name string
		arg  string
		want Resources
	}{
		{
			name: "Unmarshal List",
			arg:  fmt.Sprintf("[%s,%s]", jsonA, jsonB),
			want: resourceList,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json.Unmarshal([]byte(tt.arg), &unmarshalled_resources)
			assert.Equal(t, &tt.want, &unmarshalled_resources)
		})
	}
}
