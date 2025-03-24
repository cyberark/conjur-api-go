module github.com/cyberark/conjur-api-go

// This version has to be the lowest of the versions that we run tests with. Currently
// we test with 1.23 and 1.24 (See Jenkinsfile) so this needs to be 1.23.
go 1.23.7

require (
	github.com/Masterminds/semver/v3 v3.3.1
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.9.0
	github.com/zalando/go-keyring v0.2.6
	gopkg.in/yaml.v2 v2.4.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c => gopkg.in/yaml.v3 v3.0.1

replace golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 => golang.org/x/sys v0.8.0

replace golang.org/x/sys v0.0.0-20210819135213-f52c844e1c1c => golang.org/x/sys v0.8.0
