# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

* Add `Resource`, to fetch a resource by id.
* Add `Resources`, to show all resources, optionally filtered by a `ResourceFilter`.
* Use a separate logrus logger for the API. Control the destination for messages with the
  environment variable `CONJURAPI_LOG`.

# [0.4.0]

* Add support for `.conjurrc` and `.netrc` in Windows user directories.
* Add support for `conjur.conf` in Windows system directory.

# [0.3.3]

* Update the tags on `PolicyResponse` so they match the JSON returned by the server.

# 0.3.2

* Use github.com/sirupsen/logrus for logging.
* When the log level for logrus is set to DebugLevel, show debug information, including:

  * what configuration information is contained in each of the
    locations (e.g. the environment, config files, etc), as well as
    the final configuration
  
  * the HTTP request sent to, and the responses received from, the Conjur server
  

# 0.3.1

* Make `CONJUR_VERSION` an alias for `CONJUR_MAJOR_VERSION` to match other client libraries.

# [0.3.0]

* Adds new API methods `RotateAPIKey` and `CheckPermission`.
* Provides API methods that return secret data as an `io.ReadCloser` rather than of `[]byte`. This way, the API client gets the only copy of the secret data and can handle it however she sees fit.
* Loading a policy requires `PolicyMode` argument.
* Loading a policy returns `PolicyResponse`. 

# [0.2.0]

* Adds support for structured error responses from the Conjur v5 server, using the struct `conjurapi.ConjurError`. This is a backwards incompatible change.
* All API methods accept fully qualified object ids in v5 mode. This is a backwards compatible bug fix.
* API methods which do not work in v4 mode return an appropriate error message. This is a backwards compatible bug fix.

# 0.1.0

* Initial version

[Unreleased]: https://github.com/cyberark/conjur-api-go/compare/v0.3.3...HEAD
[0.4.0]: https://github.com/cyberark/conjur-api-go/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/cyberark/conjur-api-go/compare/v0.3.0...v0.3.3
[0.3.0]: https://github.com/cyberark/conjur-api-go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cyberark/conjur-api-go/compare/v0.1.0...v0.2.0

