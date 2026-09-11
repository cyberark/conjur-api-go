module github.com/cyberark/conjur-api-go

// This version has to be the lowest of the versions that we run tests with. Currently
// we test with 1.26 and 1.27 (See Jenkinsfile) so this needs to be 1.26.
go 1.26

require (
	github.com/Masterminds/semver/v3 v3.4.0
	github.com/aws/aws-sdk-go-v2 v1.39.1
	github.com/aws/aws-sdk-go-v2/config v1.31.10
	github.com/aws/aws-sdk-go-v2/credentials v1.18.14
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d
	github.com/oapi-codegen/runtime v1.7.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	github.com/zalando/go-keyring v0.2.6
	go.yaml.in/yaml/v3 v3.0.4
)

require (
	al.essio.dev/pkg/shellescape v1.6.0 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.5 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// These modules are pulled into the module graph only as unused,
// example/test-only dependencies of github.com/oapi-codegen/runtime (via its
// own go.mod); conjur-api-go never imports them. The replaces pin them past
// known CVEs anyway, since some SCA scanners flag the full module graph
// regardless of whether a version is actually reachable/built.
replace github.com/labstack/echo/v4 => github.com/labstack/echo/v4 v4.15.4

replace github.com/klauspost/compress => github.com/klauspost/compress v1.19.2

replace golang.org/x/net => golang.org/x/net v0.58.0

replace golang.org/x/crypto => golang.org/x/crypto v0.56.0

replace gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c => gopkg.in/yaml.v3 v3.0.1

replace golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 => golang.org/x/sys v0.8.0

replace golang.org/x/sys v0.0.0-20210819135213-f52c844e1c1c => golang.org/x/sys v0.8.0
