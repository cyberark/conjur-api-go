# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.10] - 2024-12-27

### Added
- Add functions to retrieve server version (CNJR-7207)

### Fixed
- Checks Conjur server version before using policy dry-run and fetch (CNJR-7207)

## [0.12.9] - 2024-12-13

### Added
- HTTP timeout is now configurable. [cyberark/conjur-api-go#150](https://github.com/cyberark/conjur-cli-go/issues/150)

## [0.12.8] - 2024-11-19

### Added
- Policy dry-run now returns deleted policy resources. (CNJR-6369)
- Policy dry-run now returns updated policy resources. (CNJR-6111)
- Policy dry-run now returns create policy resources. (CNJR-6110)

## [0.12.7] - 2024-11-18

### Fixed

- Updated `shellescape` package to fix Go error on installation
  [cyberark/conjur-api-go#182](https://github.com/cyberark/conjur-api-go/issues/182)

## [0.12.6] - 2024-10-30

### Security
- Remove debug logging of "Authorization" header when processing requests (CNJR-7025)

## [0.12.5] - 2024-10-23

### Added
- Added RoleMembershipsAll to fetch inherited memberships for a role (CNJR-5213)
- Added support for creating a client using an OIDC token (CNJR-6081)
- Added support for rotating the API key of an authenticated host (CNJR-5699)
- Added support for checking authenticator status (CNJR-6371)
- Return error when trying to call unsupported methods in Conjur Cloud (CNJR-5700)

## [0.12.4] - 2024-08-01

### Added
- Added support for creating hosts with annotations via HostFactory (CNJR-5495)
- Added support for enabling authenticators (CNJR-5548)
- Added support for fetching effective policy (CNJR-5673)

### Security
- Redact "Authorization" header when logging requests using CONJURAPI_LOG (CONJSE-1897)

## [0.12.3] - 2024-07-15

### Changed
- Rename `validate` query parameter to `dryRun` (CNJR-4593)

## [0.12.2] - 2024-07-15

### Changed
- Rename validate policy type definition to Dry Run (CNJR-4593)

## [0.12.1] - 2024-07-08

### Changed
- Automatically add 'api' prefix to Conjur Cloud base URLs (CNJR-5493)
- Default Account to 'conjur' for Conjur Cloud (CNJR-5494)
- Update validate policy type definition (CNJR-4593)

## [0.12.0] - 2024-05-05

### Changed
- Reworked JWT authentication to use standard configuration options (CNJR-4190)

## [0.11.4] - 2024-05-09

### Security
- Rollback to Go 1.20 as a requirement to build conjur-cli-go as FIPS
  compliant (CONJSE-1864)

## [0.11.2] - 2024-04-18

### Changed
- Added validate policy (CNJR-4539)

### Security
- Upgrade to Go 1.22 (CONJSE-1842)

## [0.11.1] - 2023-06-14

### Changed
- Improved error message for failed JWT authentication
  [cyberark/conjur-api-go#169](https://github.com/cyberark/conjur-api-go/pull/169)

### Security
- Upgrade Go to 1.20 and golang.org/x/sys to 0.8.0
  [cyberark/conjur-api-go#175](https://github.com/cyberark/conjur-api-go/pull/175)
- Upgrade ruby in bin/parse-changelog.sh from 2.5 to 3.1
  [cyberark/conjur-api-go#172](https://github.com/cyberark/conjur-api-go/pull/172)

## [0.11.0] - 2023-02-28

### Added
- Added support for Conjur's LDAP authenticator
  [cyberark/conjur-api-go#141](https://github.com/cyberark/conjur-api-go/pull/141)
- Added support for Conjur's OIDC authenticator
  [cyberark/conjur-api-go#144](https://github.com/cyberark/conjur-api-go/pull/144)
- Added `CONJUR_AUTHN_JWT_TOKEN` to support authenticating via authn-jwt with the contents of a JSON Web Token (JWT) [cyberark/conjur-api-go#143](https://github.com/cyberark/conjur-api-go/pull/140)
- Added new API method `CheckPermissionForRole`
  [cyberark/conjur-api-go#153](https://github.com/cyberark/conjur-api-go/pull/153)

### Removed
- Remove all usage of Conjur v4
  [cyberark/conjur-api-go#139](https://github.com/cyberark/conjur-api-go/pull/139)

### Changed
- Resource IDs can now be partially-qualified, adhering to the form
  `[<account>:]<kind>:<identifier>`.
  [cyberark/conjur-api-go#153](https://github.com/cyberark/conjur-api-go/pull/153)
- User and Host IDs passed to their respective API key rotation functions can
  now be fully-qualified, adhering to the form `[[<account>:]<kind>:]<identifier>`.
  [cyberark/conjur-api-go#166](https://github.com/cyberark/conjur-api-go/pull/166)
- The Hostfactory id is no longer required to be a fully qualified id.
  [cyberark/conjur-api-go#164](https://github.com/cyberark/conjur-api-go/pull/164)

### Security
- Upgrade gopkg.in/yaml.v3 indirect dependencies to v3.0.1 and Dockerfile to golang:1.19.5
  [cyberark/conjur-api-go#158](https://github.com/cyberark/conjur-api-go/pull/158)

## [0.10.2] - 2022-11-14

### Fixed
- Fixed bug with `CONJUR_AUTHN_JWT_HOST_ID` environment variable not being read
  [cyberark/conjur-api-go#136](https://github.com/cyberark/conjur-api-go/pull/136)

## [0.10.1] - 2022-06-14
### Changed
- Update testify to 1.7.2
  [cyberark/conjur-api-go#133](https://github.com/cyberark/conjur-api-go/pull/133)

## [0.10.0] - 2022-05-19

### Added
- New `CONJUR_AUTHN_JWT_HOST_ID` environment variable for authn-jwt [cyberark/conjur-api-go#130](https://github.com/cyberark/conjur-api-go/pull/130)

## [0.9.0] - 2022-02-20
### Changed
- Update Dockerfile to use Go 1.17 base image
  [cyberark/conjur-api-go#126](https://github.com/cyberark/conjur-api-go/pull/126)

### Added
- New `CONJUR_AUTHN_JWT_SERVICE_ID` & `JWT_TOKEN_PATH` environment variables as configuration to support authn-jwt
  [cyberark/conjur-api-go#124](https://github.com/cyberark/conjur-api-go/pull/124)

## [0.8.1] - 2021-12-16
### Changed
- Update Golang version to 1.17
  [cyberark/conjur-api-go#121](https://github.com/cyberark/conjur-api-go/pull/121)
- Update Golang version to 1.16.
  [cyberark/conjur-api-go#117](https://github.com/cyberark/conjur-api-go/pull/117)

## [0.8.0] - 2021-09-10
### Changed
- RetrieveBatchSecretsSafe method is updated to use the `Accept-Encoding` header
  instead of `Accept`, consistent with [recent updates on the Conjur server](https://github.com/cyberark/conjur/pull/2065).
  [cyberark/conjur-api-go#99](https://github.com/cyberark/conjur-api-go/issues/99)

### Added
- New check in RetrieveBatchSecretSafe method which will return an error if the `Content-Type` header
  is not set in the response (this indicates Conjur is out of date with the client).
  [cyberark/conjur-api-go#104](https://github.com/cyberark/conjur-api-go/issues/104)

## [0.7.1] - 2021-03-01
### Fixed
- Resources method no longer sends improperly URL-encoded query strings when
  filtering resources with the "Search" parameter. Previously, if you used a
  "Search" value that included a slash "/", the client would return no results
  even if the server had matching resources due to an issue with the URL-encoding.
  [cyberark/conjur-api-go#93](https://github.com/cyberark/conjur-api-go/issues/93)

## [0.7.0] - 2021-02-10
### Changed
- Updated Go versions to 1.15.

### Added
- RetrieveBatchSecretsSafe method, which allows the user to specify the use of the `Accept: base64`
  header in batch retrieval requests. This allows binary secrets to be retrieved from Conjur.
  [cyberark/conjur-api-go#88](https://github.com/cyberark/conjur-api-go/issues/88)

## [0.6.1] - 2020-12-02
### Changed
- Errors from YAML parsing are now breaking and visible in logs.
  [cyberark/conjur-api-go#74](https://github.com/cyberark/conjur-api-go/issues/74)

## [0.6.0] - 2019-03-04
### Added
- Converted to Golang 1.12
- Started using os.UserHomeDir() built-in instead of go-homedir module

## [0.5.2] - 2019-02-06
### Fixed
- Fixed homedir pathing for Darwin/Linux
- Converted from Godep to native go modules for dependency management.

## [0.5.1] - 2019-02-01
### Fixed
- Fix path generation of variables with spaces
- Modify configuration loading to skip options that check home dirs if there is an error retrieving the home dir

## [0.5.0] - 2018-09-07
### Added
- Add support for passing fully qualified variable id to `RetrieveSecret` API method in v4 mode
- Change signature of `conjurapi.LoadConfig` so it returns an `error` in addition to the
  `conjurapi.Config`
- Fix marshaling of `conjurapi.Config` into YAML.

## [0.4.0] - 2018-08-28
### Added
- Add `Resource`, to fetch a resource by id.
- Add `Resources`, to show all resources, optionally filtered by a `ResourceFilter`.
- Use a separate logrus logger for the API. Control the destination for messages with the environment variable `CONJURAPI_LOG`.
- Add support for `.conjurrc` and `.netrc` in Windows user directories.
- Add support for `conjur.conf` in Windows system directory.

## [0.3.3] - 2018-08-02
### Changed
- Update the tags on `PolicyResponse` so they match the JSON returned by the server.

## [0.3.2] - 2018-07-19
### Added
- Use github.com/sirupsen/logrus for logging.
- When the log level for logrus is set to DebugLevel, show debug information, including:
    - what configuration information is contained in each of the locations (e.g. the environment, config files, etc), as well as the final configuration
    -  HTTP request sent to, and the responses received from, the Conjur server
- Make `CONJUR_VERSION` an alias for `CONJUR_MAJOR_VERSION` to match other client libraries.

## [0.3.0] - 2018-01-09
### Added
- Adds new API methods `RotateAPIKey` and `CheckPermission`.
- Provides API methods that return secret data as an `io.ReadCloser` rather than of `[]byte`. This way, the API client gets the only copy of the secret data and can handle it however she sees fit.
- Loading a policy requires `PolicyMode` argument.
- Loading a policy returns `PolicyResponse`.

## [0.2.0] - 2018-01-08
### Added
- Adds support for structured error responses from the Conjur v5 server, using the struct `conjurapi.ConjurError`. This is a backwards incompatible change.
- All API methods accept fully qualified object ids in v5 mode. This is a backwards compatible bug fix.
- API methods which do not work in v4 mode return an appropriate error message. This is a backwards compatible bug fix.

## [0.1.0] - 2017-11-21
### Added
- Initial version

[Unreleased]: https://github.com/cyberark/conjur-api-go/compare/v0.12.10...HEAD
[0.12.10]: https://github.com/cyberark/conjur-api-go/compare/v0.12.9...v0.12.10
[0.12.9]: https://github.com/cyberark/conjur-api-go/compare/v0.12.8...v0.12.9
[0.12.8]: https://github.com/cyberark/conjur-api-go/compare/v0.12.7...v0.12.8
[0.12.6]: https://github.com/cyberark/conjur-api-go/compare/v0.12.5...v0.12.6
[0.12.5]: https://github.com/cyberark/conjur-api-go/compare/v0.12.4...v0.12.5
[0.12.4]: https://github.com/cyberark/conjur-api-go/compare/v0.12.3...v0.12.4
[0.12.3]: https://github.com/cyberark/conjur-api-go/compare/v0.12.2...v0.12.3
[0.12.2]: https://github.com/cyberark/conjur-api-go/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/cyberark/conjur-api-go/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/cyberark/conjur-api-go/compare/v0.11.4...v0.12.0
[0.11.4]: https://github.com/cyberark/conjur-api-go/compare/v0.11.2...v0.11.4
[0.11.2]: https://github.com/cyberark/conjur-api-go/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/cyberark/conjur-api-go/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/cyberark/conjur-api-go/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/cyberark/conjur-api-go/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/cyberark/conjur-api-go/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/cyberark/conjur-api-go/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/cyberark/conjur-api-go/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/cyberark/conjur-api-go/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/cyberark/conjur-api-go/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/cyberark/conjur-api-go/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/cyberark/conjur-api-go/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/cyberark/conjur-api-go/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/cyberark/conjur-api-go/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/cyberark/conjur-api-go/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/cyberark/conjur-api-go/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/cyberark/conjur-api-go/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cyberark/conjur-api-go/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/cyberark/conjur-api-go/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/cyberark/conjur-api-go/compare/v0.3.0...v0.3.2
[0.3.0]: https://github.com/cyberark/conjur-api-go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cyberark/conjur-api-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cyberark/conjur-api-go/releases/tag/v0.1.0
