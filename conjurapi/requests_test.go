package conjurapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnopinionatedParseID(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "simple full id",
			input: "account:kind:identifier",
			want:  []string{"account", "kind", "identifier"},
		},
		{
			name:  "simple kind and identifier",
			input: "kind:identifier",
			want:  []string{"", "kind", "identifier"},
		},
		{
			name:  "simple identifier",
			input: "identifier",
			want:  []string{"", "", "identifier"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{"", "", ""},
		},
		{
			name:  "empty string with colon",
			input: "::",
			want:  []string{"", "", ""},
		},
		{
			name:  "full id with colon",
			input: "account:kind:ident:ifier",
			want:  []string{"account", "kind", "ident:ifier"},
		},
		{
			name:  "full id with multiple colons",
			input: "account:kind:ident:ifier:extra",
			want:  []string{"account", "kind", "ident:ifier:extra"},
		},
		{
			name: "ambiguous full or partial id",
			// This is ambiguous, but we should treat it as a full id
			input: "some:variable:name",
			want:  []string{"some", "variable", "name"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			account, kind, id := unopinionatedParseID(tc.input)
			got := []string{account, kind, id}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMakeFullID(t *testing.T) {
	testCases := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "simple full id",
			input: []string{"account", "kind", "identifier"},
			want:  "account:kind:identifier",
		},
		{
			name:  "simple kind and identifier",
			input: []string{"", "kind", "identifier"},
			want:  ":kind:identifier",
		},
		{
			name:  "simple identifier",
			input: []string{"", "", "identifier"},
			want:  "::identifier",
		},
		{
			name:  "empty string",
			input: []string{"", "", ""},
			want:  "::",
		},
		{
			name:  "full id with colon",
			input: []string{"account", "kind", "ident:ifier"},
			want:  "account:kind:ident:ifier",
		},
		{
			name:  "full id with multiple colons",
			input: []string{"account", "kind", "ident:ifier:extra"},
			want:  "account:kind:ident:ifier:extra",
		},
		{
			name:  "full id in last param",
			input: []string{"", "", "account:kind:identifier"},
			want:  "account:kind:identifier",
		},
		{
			name:  "full id with colon in last param",
			input: []string{"", "", "account:kind:ident:ifier"},
			want:  "account:kind:ident:ifier",
		},
		{
			name:  "full id with multiple colons in last param",
			input: []string{"", "", "account:kind:ident:ifier:extra"},
			want:  "account:kind:ident:ifier:extra",
		},
		{
			name: "ambiguous full or partial id",
			// This is ambiguous, but we should treat it as a full id
			input: []string{"", "", "some:variable:name"},
			want:  "some:variable:name",
		},
		{
			name: "ambiguous full or partial id with matching account",
			// This is ambiguous, but we should treat it as a full id
			input: []string{"account", "variable", "account:variable:name"},
			want:  "account:variable:name",
		},
		{
			name: "ambiguous full or partial id with non-matching account",
			// This is ambiguous, but we should treat it as a partial ID since the account doesn't match
			input: []string{"account", "variable", "some:variable:name"},
			want:  "account:variable:some:variable:name",
		},
		{
			name: "ambiguous full or partial id with non-matching kind",
			// This is ambiguous, but we should treat it as a partial ID since the kind doesn't match
			input: []string{"account", "variable", "account:kind:name"},
			want:  "account:variable:account:kind:name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := makeFullID(tc.input[0], tc.input[1], tc.input[2])
			assert.Equal(t, tc.want, got)
		})
	}
}
