# v0.2.0

* Adds support for structured error responses from the Conjur v5 server, using the struct `conjurapi.ConjurError`. This is a backwards incompatible change.
* All API methods accept fully qualified object ids in v5 mode. This is a backwards compatible bug fix.
* API methods which do not work in v4 mode return an appropriate error message. This is a backwards compatible bug fix.

# v0.1.0

* Initial version
