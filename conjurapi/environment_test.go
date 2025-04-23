package conjurapi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvironmentType_Set(t *testing.T) {
	tests := []struct {
		name    string
		e       EnvironmentType
		value   string
		wantErr assert.ErrorAssertionFunc
	}{{
		name:    "Empty",
		e:       EnvironmentType(""),
		value:   "",
		wantErr: assert.Error,
	}, {
		name:    "Invalid",
		e:       EnvironmentType(""),
		value:   "invalid",
		wantErr: assert.Error,
	}, {
		name:    "Set to cloud",
		e:       EnvironmentSaaS,
		value:   "cloud",
		wantErr: assert.NoError,
	}, {
		name:    "Set to cloud short",
		e:       EnvironmentSaaS,
		value:   "CC",
		wantErr: assert.NoError,
	}, {
		name:    "Set to enterprise",
		e:       EnvironmentSH,
		value:   "enterprise",
		wantErr: assert.NoError,
	}, {
		name:    "Set to enterprise short",
		e:       EnvironmentSH,
		value:   "CE",
		wantErr: assert.NoError,
	}, {
		name:    "Set to oss",
		e:       EnvironmentOSS,
		value:   "oss",
		wantErr: assert.NoError,
	}, {
		name:    "Set to oss short",
		e:       EnvironmentOSS,
		value:   "OSS",
		wantErr: assert.NoError,
	}, {
		name:    "Set to open-source",
		e:       EnvironmentOSS,
		value:   "open-source",
		wantErr: assert.NoError,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, tt.e.Set(tt.value), fmt.Sprintf("Set(%v)", tt.value))
		})
	}
}

func TestEnvironmentType_String(t *testing.T) {
	tests := []struct {
		name string
		e    EnvironmentType
		want string
	}{{
		name: "Empty",
		e:    EnvironmentType(""),
		want: "",
	}, {
		name: "SaaS",
		e:    EnvironmentSaaS,
		want: "saas",
	}, {
		name: "Self-Hosted",
		e:    EnvironmentSH,
		want: "self-hosted",
	}, {
		name: "OSS",
		e:    EnvironmentOSS,
		want: "oss",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.e.String(), "String()")
		})
	}
}

func Test_defaultEnvironment(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want EnvironmentType
	}{{
		name: "Empty",
		url:  "",
		want: EnvironmentSH,
	}, {
		name: "Conjur Cloud",
		url:  "https://tenant.secretsmgr.cyberark.cloud",
		want: EnvironmentSaaS,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, defaultEnvironment(tt.url, false), "defaultEnvironment(%v)", tt.url)
		})
	}
}

func Test_environmentIsSupported(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"", false},
		{"cloud", true},
		{"CC", false},
		{"enterprise", true},
		{"CE", false},
		{"oss", true},
		{"OSS", true},
		{"open-source", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, environmentIsSupported(tt.name), "environmentIsSupported(%v)", tt.name)
		})
	}
}

func TestEnvironmentType_FullName(t *testing.T) {
	tests := []struct {
		name string
		e    EnvironmentType
		want string
	}{{
		"Empty",
		EnvironmentType(""),
		"Unknown Environment",
	}, {
		name: "Cloud",
		e:    EnvironmentSaaS,
		want: "Secrets Manager SaaS",
	}, {
		name: "Enterprise",
		e:    EnvironmentSH,
		want: "Secrets Manager Self-Hosted",
	}, {
		name: "OSS",
		e:    EnvironmentOSS,
		want: "Conjur Open Source",
	}, {
		name: "SaaS",
		e:    EnvironmentSaaS,
		want: "Secrets Manager SaaS",
	}, {
		name: "Self-Hosted",
		e:    EnvironmentSH,
		want: "Secrets Manager Self-Hosted",
	}, {
		name: "Unknown",
		e:    EnvironmentType("unknown"),
		want: "Unknown Environment",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.e.FullName(), "FullName()")
		})
	}
}
