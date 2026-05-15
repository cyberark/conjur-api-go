package conjurapi

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"testing"
)

func withMockBuildInfo(t *testing.T, binfo *debug.BuildInfo, ok bool) {
	t.Helper()

	prevBuildInfo := buildInfo
	prevBuildInfoOk := buildInfoOk
	prevBuildInfoOnce := buildInfoOnce

	buildInfo = binfo
	buildInfoOk = ok
	buildInfoOnce = sync.Once{}
	buildInfoOnce.Do(func() {})

	t.Cleanup(func() {
		buildInfo = prevBuildInfo
		buildInfoOk = prevBuildInfoOk
		buildInfoOnce = prevBuildInfoOnce
	})
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "trims leading v", in: "v1.2.3", want: "1.2.3"},
		{name: "keeps plain semver", in: "1.2.3", want: "1.2.3"},
		{name: "trims spaces", in: "  v2.0.0  ", want: "2.0.0"},
		{name: "devel becomes empty", in: "(devel)", want: ""},
		{name: "empty stays empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeVersion(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeVersion(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadMainVersion(t *testing.T) {
	binfo := &debug.BuildInfo{}
	binfo.Main.Version = "v1.5.0"

	got := readMainVersion(binfo)
	if got != "1.5.0" {
		t.Fatalf("readMainVersion()=%q, want %q", got, "1.5.0")
	}
}

func TestReadConjurDependencyVersion(t *testing.T) {
	binfo := &debug.BuildInfo{
		Deps: []*debug.Module{
			{Path: "example.com/other", Version: "v0.1.0"},
			{Path: conjurModulePath, Version: "v4.2.1"},
		},
	}

	got := readConjurDependencyVersion(binfo)
	if got != "4.2.1" {
		t.Fatalf("readConjurDependencyVersion()=%q, want %q", got, "4.2.1")
	}
}

func TestReadConjurDependencyVersion_UsesReplaceVersion(t *testing.T) {
	binfo := &debug.BuildInfo{
		Deps: []*debug.Module{
			{
				Path:    conjurModulePath,
				Version: "",
				Replace: &debug.Module{Path: conjurModulePath, Version: "v9.9.9"},
			},
		},
	}

	got := readConjurDependencyVersion(binfo)
	if got != "9.9.9" {
		t.Fatalf("readConjurDependencyVersion()=%q, want %q", got, "9.9.9")
	}
}

func TestReadIntegrationVersionFromEnv(t *testing.T) {
	t.Setenv("CONJUR_INTEGRATION_VERSION", "")
	t.Setenv("INTEGRATION_VERSION", "")
	t.Setenv("APP_VERSION", " v3.1.4 ")

	got := readIntegrationVersionFromEnv()
	if got != "3.1.4" {
		t.Fatalf("readIntegrationVersionFromEnv()=%q, want %q", got, "3.1.4")
	}
}

func TestReadIntegrationVersionFromVersionFiles(t *testing.T) {
	tempDir := t.TempDir()
	versionPath := filepath.Join(tempDir, "VERSION")
	if err := os.WriteFile(versionPath, []byte("v7.8.9\n"), 0o600); err != nil {
		t.Fatalf("failed to write VERSION file: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to read current dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	got := readIntegrationVersionFromVersionFiles()
	if got != "7.8.9" {
		t.Fatalf("readIntegrationVersionFromVersionFiles()=%q, want %q", got, "7.8.9")
	}
}

func TestDefaultIfNoOthers_Precedence(t *testing.T) {
	t.Run("input wins", func(t *testing.T) {
		got := defaultIfNoOthers("explicit", func() string { return "detected" }, "fallback")
		if got != "explicit" {
			t.Fatalf("defaultIfNoOthers()=%q, want %q", got, "explicit")
		}
	})

	t.Run("detected wins when input empty", func(t *testing.T) {
		got := defaultIfNoOthers("   ", func() string { return "detected" }, "fallback")
		if got != "detected" {
			t.Fatalf("defaultIfNoOthers()=%q, want %q", got, "detected")
		}
	})

	t.Run("fallback when input and detected empty", func(t *testing.T) {
		got := defaultIfNoOthers("", func() string { return "" }, "fallback")
		if got != "fallback" {
			t.Fatalf("defaultIfNoOthers()=%q, want %q", got, "fallback")
		}
	})
}

func TestReadIntegrationVersion_FallbackOrder(t *testing.T) {
	t.Run("main version has highest precedence", func(t *testing.T) {
		withMockBuildInfo(t, &debug.BuildInfo{
			Main: debug.Module{Version: "v1.2.3"},
			Deps: []*debug.Module{{Path: conjurModulePath, Version: "v9.9.9"}},
		}, true)

		t.Setenv("CONJUR_INTEGRATION_VERSION", "v8.8.8")

		got := readIntegrationVersion()
		if got != "1.2.3" {
			t.Fatalf("readIntegrationVersion()=%q, want %q", got, "1.2.3")
		}
	})

	t.Run("dependency version used when main unavailable", func(t *testing.T) {
		withMockBuildInfo(t, &debug.BuildInfo{
			Main: debug.Module{Version: "(devel)"},
			Deps: []*debug.Module{{Path: conjurModulePath, Version: "v4.5.6"}},
		}, true)

		got := readIntegrationVersion()
		if got != "4.5.6" {
			t.Fatalf("readIntegrationVersion()=%q, want %q", got, "4.5.6")
		}
	})

	t.Run("env used when build info unavailable", func(t *testing.T) {
		withMockBuildInfo(t, nil, false)
		t.Setenv("CONJUR_INTEGRATION_VERSION", "")
		t.Setenv("INTEGRATION_VERSION", "v3.4.5")
		t.Setenv("APP_VERSION", "v9.9.9")

		got := readIntegrationVersion()
		if got != "3.4.5" {
			t.Fatalf("readIntegrationVersion()=%q, want %q", got, "3.4.5")
		}
	})

	t.Run("version file used when build info and env are empty", func(t *testing.T) {
		withMockBuildInfo(t, nil, false)
		t.Setenv("CONJUR_INTEGRATION_VERSION", "")
		t.Setenv("INTEGRATION_VERSION", "")
		t.Setenv("APP_VERSION", "")

		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, "VERSION"), []byte("v6.7.8\n"), 0o600); err != nil {
			t.Fatalf("failed to write VERSION file: %v", err)
		}

		oldWD, err := os.Getwd()
		if err != nil {
			t.Fatalf("failed to read current dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(oldWD) })

		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("failed to chdir: %v", err)
		}

		got := readIntegrationVersion()
		if got != "6.7.8" {
			t.Fatalf("readIntegrationVersion()=%q, want %q", got, "6.7.8")
		}
	})
}

func TestNew_FallbackResolution(t *testing.T) {
	t.Run("explicit values override detected/default values", func(t *testing.T) {
		withMockBuildInfo(t, &debug.BuildInfo{Main: debug.Module{Path: "github.com/example/app", Version: "v9.9.9"}}, true)

		tel := NewTelemetry("MySDK", "Plugin", "2.3.4", "MyVendor", "1.0.0")
		if tel.IntegrationName != "MySDK" || tel.IntegrationType != "Plugin" || tel.IntegrationVersion != "2.3.4" || tel.VendorName != "MyVendor" || tel.VendorVersion != "1.0.0" {
			t.Fatalf("New() did not preserve explicit values: %+v", tel)
		}
	})

	t.Run("empty values use detected/default fallback chain", func(t *testing.T) {
		withMockBuildInfo(t, &debug.BuildInfo{Main: debug.Module{Path: "github.com/cyberark/conjur-api-go", Version: "v5.0.1"}}, true)

		tel := NewTelemetry("", "", "", "", "")
		if tel.IntegrationName != "conjur-api-go" {
			t.Fatalf("IntegrationName=%q, want %q", tel.IntegrationName, "conjur-api-go")
		}
		if tel.IntegrationType != IntegrationType {
			t.Fatalf("IntegrationType=%q, want %q", tel.IntegrationType, IntegrationType)
		}
		if tel.IntegrationVersion != "5.0.1" {
			t.Fatalf("IntegrationVersion=%q, want %q", tel.IntegrationVersion, "5.0.1")
		}
		if tel.VendorName != VendorName {
			t.Fatalf("VendorName=%q, want %q", tel.VendorName, VendorName)
		}
		if tel.VendorVersion != VendorVersion {
			t.Fatalf("VendorVersion=%q, want %q", tel.VendorVersion, VendorVersion)
		}
	})
}
