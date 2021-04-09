# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- RetrieveBatchSecretsSafe method is updated to use the `Accept-Encoding` header
  instead of `Accept`, consistent with [recent updates on the Conjur server](https://github.com/cyberark/conjur/pull/2065).
  [cyberark/conjur-api-go#99](https://github.com/cyberark/conjur-api-go/issues/99)

### Added
- New check in RetrieveBatchSecretSafe method which will return an error if the `Content-Type` header
  is not set in the response (this indicates Conjur is out of date with the client).
  [cyberark/conjur-api-go#104](https://github.com/cyberark/conjur-api-go/issues/104)
- ResourcesRequest is now supported for v4 conjur instances.

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

[Unreleased]: https://github.com/cyberark/conjur-api-go/compare/v0.7.1...HEAD
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
