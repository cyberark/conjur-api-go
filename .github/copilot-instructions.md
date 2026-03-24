# conjur-api-go — Copilot Instructions

## Project overview

This is the official Go SDK for the CyberArk Conjur secrets management API.
Module path: `github.com/cyberark/conjur-api-go`
All SDK code lives under `conjurapi/`. Tests live alongside source (`*_test.go`).

## Architecture

### Core types
- **`Config`** (`conjurapi/config.go`) — all connection and authentication settings; populated from struct fields, YAML, or environment variables. Every new auth method needs fields here plus entries in `mergeEnv()` and `merge()`.
- **`Client`** (`conjurapi/client.go`) — the main API surface; constructed via `NewClient`, `NewClientFromEnvironment`, or an auth-specific constructor (e.g. `NewClientFromCertificate`). HTTP client creation happens in `createHttpClient()` — this is the right place to wire transport-level concerns (mTLS, HTTPS, proxy).
- **`Authenticator` interface** (`conjurapi/authn/`) — each auth method implements `RefreshToken() ([]byte, error)` and `NeedsTokenRefresh() bool`. Keep authenticators thin: they call a `func` reference set post-construction; they do not own the HTTP client.

### Adding a new authenticator — files to touch
| File | What to add |
|---|---|
| `conjurapi/authn/<name>_authenticator.go` | Authenticator struct + interface impl |
| `conjurapi/config.go` | Config fields, `supportedAuthnTypes`, `Validate()`, `merge()`, `mergeEnv()` |
| `conjurapi/client.go` | `createHttpClient()` branch (if transport changes needed), `NewClientFrom<Name>` constructor |
| `conjurapi/requests.go` | `<Name>AuthenticateRequest()` |
| `conjurapi/authn.go` | `<Name>Authenticate()` method on `Client` |

### OSS vs Enterprise
- Conjur OSS and Conjur Enterprise (appliance) share most of the API surface.
- Features not available on Conjur Cloud (SaaS) must be guarded with `isConjurCloudURL(c.ApplianceURL)` and return an explicit error — see `CertAuthenticate`, `Login`, `RotateAPIKey` for the pattern.

### `_v2` suffix convention
Files ending in `_v2.go` / `_v2_test.go` implement newer Conjur Enterprise REST endpoints not yet available in Open Source.

## Testing

### Two test modes

**Unit / mock tests** — no live server needed; use `createMockConjurClient` from `conjurapi/mock_conjur_test.go`.

**Integration tests** — require a live Conjur instance. The harness is `NewTestUtils(&Config{})` which reads connection details from environment variables set by `bin/start-conjur.sh`.

### Running tests
```shell
# All tests (OSS Conjur in Docker)
./bin/test.sh

# Cert auth integration tests (requires Enterprise appliance image)
TEST_CERT=true ./bin/test.sh

# Single test during development
./bin/dev.sh   # opens a shell in the dev container
go test -v -run TestMyTest ./conjurapi/...
```

### Integration test skip-guard pattern
Every integration test that requires a live server or special credentials must open with:
```go
if strings.ToLower(os.Getenv("TEST_SOMETHING")) != "true" {
    t.Skip("Skipping ... Set TEST_SOMETHING=true to enable.")
}
```

### `NewTestUtils` / `SetupWithAuthenticator`
Integration tests use `NewTestUtils` to get an admin client, then `utils.SetupWithAuthenticator("cert", policyYAML, rolesYAML)` to load policy. Always `require.NoError` on setup — a 401 here means the admin API key env var was not set.

### Cert client config inherits server TLS cert
When building a cert-auth client inside a test, copy `SSLCert` / `SSLCertPath` from the admin client's config so the mTLS transport can verify the server certificate:
```go
config := Config{
    ApplianceURL:      conjur.config.ApplianceURL,
    Account:           conjur.config.Account,
    SSLCert:           conjur.config.SSLCert,
    SSLCertPath:       conjur.config.SSLCertPath,
    AuthnType:         "cert",
    ...
}
```

## Environment variables

| Variable | Purpose |
|---|---|
| `CONJUR_APPLIANCE_URL` | Base URL of the Conjur server |
| `CONJUR_ACCOUNT` | Conjur account name |
| `CONJUR_AUTHN_LOGIN` | Admin username |
| `CONJUR_AUTHN_API_KEY` | Admin API key |
| `CONJUR_SSL_CERTIFICATE` | Inline PEM for server TLS verification |
| `CONJUR_CERT_FILE` | Path to server TLS cert file |
| `CONJUR_AUTHN_CERT_FILE` | Path to client cert PEM (authn-cert) |
| `CONJUR_AUTHN_CERT_KEY_FILE` | Path to client key PEM (authn-cert) |
| `CONJUR_AUTHN_CERT_HOST_ID` | Conjur host ID for authn-cert request mode |
| `CONJUR_AUTHN_CERT_SERVICE_ID` | Sets `AuthnType=cert` + `ServiceID` implicitly |
| `TEST_CERT` | Set to `true` to run authn-cert integration tests |
| `TEST_CERT_CA_CERT` | Inline PEM of the issuing CA for authn-cert |

## Key conventions

- **Env var naming**: `CONJUR_AUTHN_<TYPE>_<FIELD>` for authenticator-specific fields.
- **Inline PEM vs path**: Config fields come in pairs — `FooCert` (inline PEM, `yaml:"-"`) and `FooCertPath` (file path). Inline takes precedence in `ReadFoo()` helpers.
- **No credential logging**: Inline PEM/key fields must be redacted in `Config.String()` — see the `[REDACTED]` pattern there.
- **SaaS guard**: Any feature unavailable on Conjur Cloud must call `isConjurCloudURL` early and return a descriptive error.
- **`evoke` vs `conjurctl`**: `evoke` is the Enterprise appliance CLI. `conjurctl` is OSS-only. Never use `conjurctl` in scripts targeting the Enterprise appliance.
- **`exec_on` helper**: Defined in `bin/utils.sh`; uses `docker compose ps -q <service>`. For the Enterprise appliance (fixed `container_name: conjur-leader-1.mycompany.local`), use `docker exec conjur-leader-1.mycompany.local` directly.

## Docker Compose profiles

| Profile | Services started | When used |
|---|---|---|
| _(default)_ | `postgres`, `conjur` | All standard tests |
| `cert` | + `conjur-leader` (Enterprise appliance) | `TEST_CERT=true` |

The `conjur-leader` container has a **fixed `container_name`** outside the Compose project namespace. It must be explicitly removed before re-running: `docker rm -f conjur-leader-1.mycompany.local`. The `cert` profile is managed by `bin/setup-cert-auth.sh`.
