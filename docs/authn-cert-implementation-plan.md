# Implementation Plan: Certificate Authenticator (`authn-cert`)

## Background

CyberArk Secrets Manager 13.8 introduced support for a [Certificate Authenticator](https://docs.cyberark.com/secrets-manager-sh/latest/en/content/operations/authn/authn-cert/authn-cert.htm), which allows workloads to authenticate using an X.509 client certificate over mutual TLS (mTLS). This document describes the plan for adding first-class support to this SDK.

### How it works

Rather than exchanging a credential in the request body (as with API key, JWT, etc.), the workload presents its client certificate and private key during the TLS handshake itself. On success, Conjur returns a standard access token.

```
POST /authn-cert/<service-id>/<account>[/<url-encoded-host-id>]/authenticate
Accept-Encoding: base64
```

There are two server-side host resolution modes:

| Mode | Host ID in URL | How host is resolved |
|---|---|---|
| `request` (default) | Required | Caller supplies the Conjur host ID in the URL; at least one workload annotation must match the cert fields |
| `spiffe` | Omitted | Host is derived automatically from the SPIFFE ID in the cert's SAN URI |

---

## Assumptions

- Client certificates are provisioned out-of-band (e.g., by an internal PKI or SPIFFE/SPIRE). The SDK is not responsible for certificate lifecycle management.
- The certificate and private key may be supplied as PEM file paths or inline PEM strings — consistent with how `SSLCert`/`SSLCertPath` work today.
- SPIFFE mode is supported by leaving `HostID` empty; the SDK makes no attempt to parse or validate the SPIFFE ID itself.
- `authn-cert` is not supported in Secrets Manager SaaS (Conjur Cloud) at this time, consistent with other self-hosted-only authenticators.

---

## Risks & Edge Cases

- **Certificate expiry**: the mTLS handshake will fail with a TLS error when the client certificate expires. When file paths are used, cert rotation is transparent (see Phase 3). When inline PEM is used, callers must construct a new `Client` after rotation.
- **Proxy interaction**: mTLS and HTTP proxies (`CONNECT` tunnels) can interact poorly if the proxy terminates TLS. The existing `cfg.ProxyURL()` will be preserved in the transport; no special handling is added.

---

## Phase 1 — `CertAuthenticator` struct

**New file: `conjurapi/authn/cert_authenticator.go`**

Follows the same minimal pattern as `APIKeyAuthenticator` and `OidcAuthenticator`. No credential-fetching logic: the certificate is ambient in the transport layer.

```go
type CertAuthenticator struct {
    // HostID is the URL-encoded Conjur host path (e.g. "host/vm-workloads/vm-01").
    // Leave empty for SPIFFE mode — the host is derived from the cert's SPIFFE SAN URI.
    HostID string
    // Authenticate POSTs to the authn-cert endpoint and returns a Conjur access token.
    // It is set to Client.CertAuthenticate after client construction.
    Authenticate func(hostID string) ([]byte, error)
}

func (a *CertAuthenticator) RefreshToken() ([]byte, error) {
    return a.Authenticate(a.HostID)
}

func (a *CertAuthenticator) NeedsTokenRefresh() bool {
    return false
}
```

**New file: `conjurapi/authn/cert_authenticator_test.go`**

Unit test coverage:
- `RefreshToken()` delegates to `Authenticate` with the configured `HostID`
- `RefreshToken()` with empty `HostID` (SPIFFE mode) passes empty string through
- `RefreshToken()` propagates `Authenticate` errors
- `NeedsTokenRefresh()` always returns `false`

---

## Phase 2 — Config

**`conjurapi/config.go`**

### New fields

```go
ClientCertFile    string `yaml:"client_cert_file,omitempty"`
ClientCertKeyFile string `yaml:"client_cert_key_file,omitempty"`
ClientCert        string `yaml:"-"` // inline PEM; never written to disk
ClientCertKey     string `yaml:"-"` // inline PEM; never written to disk
```

Pattern mirrors the existing `SSLCertPath`/`SSLCert` fields. `yaml:"-"` ensures secrets are never accidentally serialized.

### `supportedAuthnTypes`

Add `"cert"` to the slice.

### `Validate()` additions

```
"cert" requires ServiceID
"cert" requires ClientCertFile or ClientCert
"cert" requires ClientCertKeyFile or ClientCertKey
JWTHostID (HostID) is optional for "cert" (required only for request mode)
"cert" combined with a detected Conjur Cloud URL returns an error early
```

The last point mirrors the pattern used in `Login()`, `ChangeUserPassword()` and `RotateAPIKey()`, but moves the check to validation time so developers get feedback before making any network calls.

### Private key redaction in debug logging

`Validate()` emits `fmt.Sprintf("config: %+v", c)` at debug level. `yaml:"-"` prevents YAML serialization but `%+v` still prints every field, meaning `ClientCert` and `ClientCertKey` (inline PEM) would be written to any `CONJURAPI_LOG` target. Implement a `String()` method on `Config` that redacts `ClientCert` and `ClientCertKey`, consistent with the existing `redactHeaders()` approach in `response/response.go`:

```go
func (c Config) String() string {
    c.ClientCert = "[REDACTED]"
    c.ClientCertKey = "[REDACTED]"
    return fmt.Sprintf("%+v", c)
}
```

Add a corresponding test asserting that debug output never contains the literal PEM header `-----BEGIN`.

### `merge()` additions

Include the four new fields.

### `mergeEnv()` additions

`mergeEnv()` maps every config field to a `CONJUR_*` env var. New mappings:

| Env var | Config field |
|---|---|
| `CONJUR_AUTHN_CERT_FILE` | `ClientCertFile` |
| `CONJUR_AUTHN_CERT_KEY_FILE` | `ClientCertKeyFile` |

Additionally, following the `CONJUR_AUTHN_JWT_SERVICE_ID` precedent, when `CONJUR_AUTHN_CERT_SERVICE_ID` is set it implicitly sets `AuthnType = "cert"` and overrides `ServiceID`. This allows zero-code-change adoption via environment variables alone.

### New helper

```go
func (c *Config) ReadClientCert() (tls.Certificate, error)
```

Loads the `tls.Certificate` pair from inline PEM content or files, preferring inline content (same precedence as `SSLCert` over `SSLCertPath`).

---

## Phase 3 — mTLS HTTP Transport

**`conjurapi/client.go`**

The mTLS client certificate must be present in `tls.Config.Certificates` at transport creation time — not in the request itself.

### `createHttpClient()` change

When `config.AuthnType == "cert"`, the client cert must be present in the transport regardless of whether a custom CA cert is provided. The logic:

```go
if config.AuthnType == "cert" {
    clientCert, err := config.ReadClientCert()
    if err != nil {
        return nil, err
    }
    var caCert []byte
    if config.IsHttps() {
        caCert, err = config.ReadSSLCert()
        if err != nil {
            return nil, err
        }
    }
    return newMTLSClient(caCert, clientCert, config)
}
```

This ensures cert auth with no custom CA still attaches the client cert to the system-trust-store transport rather than erroring out. The existing `IsHttps()` / `newHTTPSClient()` path is left untouched.

### New `newMTLSClient(caCert []byte, clientCert tls.Certificate, config Config)`

Builds a transport with the client cert for mTLS, and optionally a custom CA cert pool for server verification.

**Transparent cert rotation via `GetClientCertificate`**

Rather than pre-loading into `tls.Config.Certificates` (static, requires client reconstruction on rotation), use the `GetClientCertificate` callback which is invoked per TLS handshake. When `ClientCertFile`/`ClientCertKeyFile` are configured, the callback re-reads the files on each handshake, making cert rotation transparent to long-running workloads. When inline PEM (`ClientCert`/`ClientCertKey`) is used, it returns the pre-loaded cert (callers must reconstruct the client to rotate):

```go
tr := newHTTPTransport(config)
tlsCfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
        // Re-read from disk on each handshake when file paths are configured,
        // enabling transparent certificate rotation.
        cert, err := config.ReadClientCert()
        if err != nil {
            return nil, err
        }
        return &cert, nil
    },
}
if len(caCert) > 0 {
    pool := x509.NewCertPool()
    if !pool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("Can't append Secrets Manager SSL cert")
    }
    tlsCfg.RootCAs = pool
}
tr.TLSClientConfig = tlsCfg
return &http.Client{Transport: tr, Timeout: time.Second * time.Duration(config.GetHttpTimeout())}, nil
```

**TLS minimum version** is explicitly set to `tls.VersionTLS12`. The Conjur cert authenticator supports TLS 1.2 and 1.3; allowing lower versions in the default Go TLS config would be inconsistent with the server's documented minimum.

---

## Phase 4 — Request Builder & Authenticate Method

**`conjurapi/requests.go` — `CertAuthenticateRequest`**

```go
func (c *Client) CertAuthenticateRequest(hostID string) (*http.Request, error) {
    var authenticateURL string
    if hostID != "" {
        authenticateURL = makeRouterURL(
            c.authnURL(c.config.AuthnType, c.config.ServiceID),
            url.PathEscape(ensureHostPrefix(hostID)), "authenticate").String()
    } else {
        authenticateURL = makeRouterURL(
            c.authnURL(c.config.AuthnType, c.config.ServiceID), "authenticate").String()
    }
    req, err := http.NewRequest(http.MethodPost, authenticateURL, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept-Encoding", "base64")
    req.Header.Add(ConjurSourceHeader, c.GetTelemetryHeader())
    return req, nil
}
```

The existing `authnURL()` already produces the correct path for `"cert"` via its generic fallthrough branch: `authn-cert/<service-id>/<account>`. No change to `authnURL()` is needed.

**`conjurapi/authn.go` — `CertAuthenticate`**

```go
func (c *Client) CertAuthenticate(hostID string) ([]byte, error) {
    if isConjurCloudURL(c.config.ApplianceURL) {
        return nil, errors.New("Certificate authentication is not supported in Secrets Manager SaaS")
    }
    req, err := c.CertAuthenticateRequest(hostID)
    if err != nil {
        return nil, err
    }
    logging.ApiLog.Debugf("Authenticating with authn-cert, service ID: %s", c.config.ServiceID)
    res, err := c.submitRequestWithCustomAuth(req)
    if err != nil {
        return nil, err
    }
    return response.DataResponse(res)
}
```

Uses `submitRequestWithCustomAuth` (bypasses `createAuthRequest`) because no `Authorization: Token` header is needed — the identity is established at the TLS layer.

The **SaaS guard** (`isConjurCloudURL`) mirrors the pattern in `ChangeUserPassword`, `Login`, and `RotateAPIKey`. Without it, a SaaS user would receive an opaque TLS handshake failure rather than a clear unsupported-operation message.

---

## Phase 5 — Client Constructors & Environment Wiring

**`conjurapi/client.go`**

### New constructor

```go
func NewClientFromCertificate(config Config) (*Client, error) {
    authenticator := &authn.CertAuthenticator{
        HostID: config.JWTHostID,
    }
    client, err := newClientWithAuthenticator(config, authenticator)
    if err == nil {
        authenticator.Authenticate = client.CertAuthenticate
    }
    return client, err
}
```

`newClientWithAuthenticator` → `NewClient` → `createHttpClient` → detects `AuthnType == "cert"` → builds mTLS transport automatically.

### `NewClientFromEnvironment()` addition

Add a branch before the stored-credentials fallback:

```go
if config.AuthnType == "cert" {
    return newClientFromCertConfig(config)
}
```

### `newClientFromCertConfig()`

Mirrors the pattern of `newClientFromStoredAWSConfig` / `newClientFromStoredAzureConfig`:

```go
func newClientFromCertConfig(config Config) (*Client, error) {
    client, err := NewClientFromCertificate(config)
    if err != nil {
        return nil, err
    }
    err = client.RefreshToken()
    if err != nil {
        return nil, err
    }
    return client, nil
}
```

---

## Phase 6 — Tests

### `conjurapi/authn/cert_authenticator_test.go` (unit)

Follows the shape of `api_key_authenticator_test.go` and `oidc_authenticator_test.go`:

- `RefreshToken()` delegates to `Authenticate` with the configured `HostID`
- `RefreshToken()` with empty `HostID` passes empty string through (SPIFFE mode)
- `RefreshToken()` propagates errors from `Authenticate`
- `NeedsTokenRefresh()` always returns `false`

### `conjurapi/config_test.go` additions

Follows the table-driven pattern in `TestConfig_Validate`:

- Valid cert config (with `ServiceID`, `ClientCertFile`, `ClientCertKeyFile`) passes
- Missing `ServiceID` returns error containing `"Must specify a ServiceID when using cert"`
- Missing cert material returns appropriate error
- `"cert"` with `JWTHostID` empty passes (SPIFFE mode)
- `"cert"` with a Conjur Cloud `ApplianceURL` returns an error
- Debug log output for a failing cert config never contains `-----BEGIN` (private key redaction)

### `conjurapi/requests_test.go` additions

- `CertAuthenticateRequest` with host ID produces `authn-cert/<service-id>/<account>/host%2F<id>/authenticate`
- `CertAuthenticateRequest` without host ID produces `authn-cert/<service-id>/<account>/authenticate`
- Request has `Accept-Encoding: base64` header

### `conjurapi/client_test.go` additions

Follows the `TestNewClientFromJwt` pattern, using a `mockConjurServerWithCert()` helper:

```go
func mockConjurServerWithCert() *httptest.Server
```

**Important:** because cert auth is mTLS, this helper must use `httptest.NewTLSServer` configured to request client certificates (`tls.RequireAnyClientCert`). Test fixture certs should be generated at test time using `crypto/x509` and `crypto/ecdsa` — _not_ stored as static files — so they are always valid and never need rotation.

Test cases for `TestNewClientFromCertificate`:
- Has authenticator of type `*authn.CertAuthenticator`
- Successful `RefreshToken()` with host ID in URL (request mode)
- Successful `RefreshToken()` with empty host ID (SPIFFE mode — no host segment in URL)
- `RefreshToken()` returns error on 401
- Returns error when `SSLCertPath` is invalid
- Returns error when `ClientCertFile` is invalid

`TestNewClientFromEnvironment` addition:
- `"Calls NewClientFromCertificate when AuthnType is cert"` — asserts `assert.IsType(t, &authn.CertAuthenticator{}, client.authenticator)`

### `conjurapi/authn_cert_test.go` (integration)

Follows the `authn_iam_test.go` / `authn_azure_test.go` pattern:

- Skip guard: `TEST_CERT != "true"`
- Uses `utils.SetupWithAuthenticator("cert", ...)` with policy templates for a cert authenticator and workload host
- Sets the `ca-cert` variable on the authenticator
- Calls `conjur.EnableAuthenticator("cert", serviceID, true)`
- Constructs `Config` with `AuthnType: "cert"`, `ServiceID`, `JWTHostID`, `ClientCertFile`, `ClientCertKeyFile`
- Asserts `certConjur.GetAuthenticator().RefreshToken()` succeeds
- Asserts `WhoAmI()` contains the expected host ID
- Asserts a secret can be retrieved

---

## Phase 7 — Documentation

- Add an entry to `CHANGELOG.md` under `Unreleased`
- Add a cert auth usage example to `README.md`

---

## Technical Debt

The following items are out of scope for this effort but should be tracked:

1. **`JWTHostID` is semantically overloaded.** The field now applies to JWT, IAM, Azure, and cert auth, but its name implies JWT only. A future refactor should introduce a first-class `HostID` field and deprecate `JWTHostID`.

2. **No explicit `CertHostMode` config field.** The SDK cannot know whether the server is in `request` or `spiffe` mode. An empty `JWTHostID` silently enables SPIFFE mode. A future improvement could add a `CertHostMode` config field (`"request"` / `"spiffe"`) to make the intent explicit and allow earlier validation.
