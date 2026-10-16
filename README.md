# Idira™ Secrets Manager by Palo Alto Networks API for Go

Programmatic Golang access to the Idira Secrets Manager API.

## Certification level
![](https://img.shields.io/badge/Certification%20Level-Community-28A745?link=https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

This repo is a **Community** level project. It's a community contributed project that **is not reviewed or supported
by Palo Alto Networks Idira™**. For more detailed information on our certification levels, see [our community guidelines](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md#community).

## Using conjur-api-go with Conjur Open Source

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html).
Conjur maintainers perform additional testing on the suite release versions to ensure
compatibility. When possible, upgrade your Conjur version to match the
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm);
when using integrations, choose the latest suite release that matches your Conjur version. For any
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

## Compatibility

The `conjur-api-go` has been tested against the following Go versions:

- 1.26
- 1.27

## Installation

```sh
go get github.com/cyberark/conjur-api-go/conjurapi
```

## Quick Start

This example demonstrates how to retrieve a secret from Conjur.

Suppose there exists a variable `db/secret` with secret value `fde5c4a45ce573f9768987cd`. Create a Go program using `conjur-api-go` to fetch the secret value:

```go
package main

import (
    "os"
    "fmt"
    "github.com/cyberark/conjur-api-go/conjurapi"
    "github.com/cyberark/conjur-api-go/conjurapi/authn"
)

func main() {
    variableIdentifier := "db/secret"

    config, err := conjurapi.LoadConfig()
    if err != nil {
        panic(err)
    }

    conjur, err := conjurapi.NewClientFromKey(config,
        authn.LoginPair{
            Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
            APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
        },
    )
    if err != nil {
        panic(err)
    }

    // Retrieve a secret into []byte.
    secretValue, err := conjur.RetrieveSecret(variableIdentifier)
    if err != nil {
        panic(err)
    }
    fmt.Println("The secret value is: ", string(secretValue))

    // Retrieve a secret into io.ReadCloser, then read into []byte.
    // Alternatively, you can transfer the secret directly into secure memory,
    // vault, keychain, etc.
    secretResponse, err := conjur.RetrieveSecretReader(variableIdentifier)
    if err != nil {
        panic(err)
    }

    secretValue, err = conjurapi.ReadResponseBody(secretResponse)
    if err != nil {
        panic(err)
    }
    fmt.Println("The secret value is: ", string(secretValue))
}
```

Build and run the program:

```bash
$ export CONJUR_APPLIANCE_URL=https://eval.conjur.org
$ export CONJUR_ACCOUNT=myorg
$ export CONJUR_AUTHN_LOGIN=mylogin
$ export CONJUR_AUTHN_API_KEY=myapikey
$ go run main.go
The secret value is: fde5c4a45ce573f9768987cd
```

## Usage

### Configuration and Authentication

Connecting to Idira Secrets Manager requires two steps:

1. **Configuration** - Specify the Idira Secrets Manager endpoint and connection security settings
2. **Authentication** - Provide credentials for authentication

### Credential Storage

The Conjur Go API supports three credential storage backends, configurable via the `CredentialStorage` field in the `Config` struct:

#### Storage backends

- **`conjurapi.CredentialStorageKeyring`** - Stores credentials in the system keyring (default when available). This is the most secure option for desktop environments.
- **`conjurapi.CredentialStorageFile`** - Stores credentials in a `.netrc` file (default when keyring is not available). The `.netrc` file location can be customized using the `NetRCPath` config field.
- **`conjurapi.CredentialStorageNone`** - Does not store credentials. **Use this option in environments where there are no file permissions to create a `.netrc` file**, such as restricted containers, read-only filesystems, or ephemeral compute instances.

> **Note:** If no credential storage is specified, the API will automatically select `CredentialStorageKeyring` if available, otherwise it will default to `CredentialStorageFile`.

#### Storage mode (read/write policy)

Separate from the backend selection, `CredentialStorageMode` controls whether the configured backend accepts writes:

- **`conjurapi.CredentialStorageModeReadWrite`** (default) - Read and write cached credentials.
- **`conjurapi.CredentialStorageModeReadOnly`** - Read cached credentials but suppress writes (no error).

Configure the effective mode using (highest precedence first):

1. An explicit `Config.CredentialStorageMode` field (struct literal or merged config)
2. `CONJUR_CREDENTIAL_STORAGE_MODE` environment variable (`readwrite` or `readonly`, case-insensitive). This variable is read by the Go library when loading config; it is not a Conjur appliance or CLI setting.
3. `conjurapi.WithDefaultCredentialStorageMode(mode)` when env is unset (used by integrators such as summon)
4. Library fallback: `CredentialStorageModeReadWrite`

`CredentialStorageModeReadOnly` still creates the configured storage provider and allows reads; it only suppresses writes. `CredentialStorageNone` disables storage entirely.

```go
conjurapi.WithDefaultCredentialStorageMode(conjurapi.CredentialStorageModeReadOnly)
config, _ := conjurapi.LoadConfig()
client, err := conjurapi.NewClientFromEnvironment(config)
```

#### Keyring namespace isolation

When using keyring storage, set `KeychainNamespace` on `Config` (YAML key `keychain_namespace`) or the `CONJUR_KEYCHAIN_NAMESPACE` environment variable to scope keyring entries per invocation. The effective keyring service name is `machineName:namespace` when a namespace is set, or the existing machine name when unset. Precedence matches other resolved config: an explicit non-empty `Config` value wins over the environment; when loading from files, environment overrides YAML. `LoadConfig` freezes namespace resolution so a later `Validate` does not re-apply env; on hand-built `Config` values, call `SetKeychainNamespaceResolved(true)` after clearing `KeychainNamespace` if env should not refill it. Namespaces must not be empty and cannot contain `/`, `\`, `:`, or null bytes.

For file-based credential storage, use `CONJUR_NETRC_PATH` to isolate `.netrc` files per invocation.

#### Example: Disabling Credential Storage

```go
config := conjurapi.Config{
    ApplianceURL:      "https://conjur.example.com",
    Account:           "myorg",
    CredentialStorage: conjurapi.CredentialStorageNone,
}

conjur, err := conjurapi.NewClientFromKey(config,
    authn.LoginPair{
        Login:  "mylogin",
        APIKey: "myapikey",
    },
)
```

### Authentication Methods

All authentication methods require the following common configuration. Use `conjurapi.LoadConfig()` to load configuration from environment variables.

| Config Field | Environment Variable | Required | Description |
|---|---|---|---|
| `Account` | `CONJUR_ACCOUNT` | Yes | Conjur account name |
| `ApplianceURL` | `CONJUR_APPLIANCE_URL` | Yes | Conjur server URL |
| `SSLCertPath` | `CONJUR_CERT_FILE` | No | Path to Conjur SSL certificate file |
| `SSLCert` | `CONJUR_SSL_CERTIFICATE` | No | Inline PEM content of the Conjur SSL certificate |

> **Note:** If both `CONJUR_SSL_CERTIFICATE` and `CONJUR_CERT_FILE` are set,
> the inline PEM (`CONJUR_SSL_CERTIFICATE`) takes precedence and the file path
> is ignored. A warning is logged to help surface this misconfiguration.

#### API Key

```go
conjur, err := conjurapi.NewClientFromKey(config, authn.LoginPair{Login: "mylogin", APIKey: "myapikey"})
```

See the [Quick Start](#quick-start) example for full usage.

#### JWT

Authenticate with a JWT token. Automatically selected by `NewClientFromEnvironment()` when `CONJUR_AUTHN_JWT_SERVICE_ID` is set. Falls back to reading the Kubernetes service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` if no token is provided.

| Config Field | Environment Variable | Required | Description |
|---|---|---|---|
| `AuthnType` | `CONJUR_AUTHN_TYPE` | Yes | Must be `"jwt"` (set automatically by `CONJUR_AUTHN_JWT_SERVICE_ID`) |
| `ServiceID` | `CONJUR_AUTHN_JWT_SERVICE_ID` / `CONJUR_SERVICE_ID` | Yes | JWT authenticator service ID |
| `JWTContent` | `CONJUR_AUTHN_JWT_TOKEN` | Yes* | JWT token content |
| `JWTFilePath` | `JWT_TOKEN_PATH` | Yes* | Path to a file containing the JWT token |
| `JWTHostID` | `CONJUR_AUTHN_JWT_HOST_ID` | No | Host identity for JWT authentication |

\* Provide either `JWTContent` or `JWTFilePath`. If `JWTFilePath` is set, the token is read from that file.

```go
conjur, err := conjurapi.NewClientFromJwt(config)
// Or via NewClientFromEnvironment (auto-detected when CONJUR_AUTHN_JWT_SERVICE_ID is set):
conjur, err := conjurapi.NewClientFromEnvironment(config)
```

#### AWS IAM

Authenticate using AWS IAM credentials. The client signs an AWS STS `GetCallerIdentity` request and sends the signed headers to Conjur. Credentials are loaded via the AWS SDK default credential chain (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`). Defaults to region `us-east-1`.

| Config Field | Environment Variable | Required | Description |
|---|---|---|---|
| `AuthnType` | `CONJUR_AUTHN_TYPE` | Yes | Must be `"iam"` |
| `ServiceID` | `CONJUR_SERVICE_ID` | Yes | IAM authenticator service ID |
| `JWTHostID` | `CONJUR_AUTHN_JWT_HOST_ID` | Yes | Conjur host ID (AWS IAM role identifier) |

```go
config.AuthnType = "iam"
config.ServiceID = "prod"
config.JWTHostID = "myapp/aws-role"
conjur, err := conjurapi.NewClientFromAWSCredentials(config)
```

#### Azure

Authenticate using an Azure managed identity token from the Instance Metadata Service (IMDS). Supports system-assigned and user-assigned identities.

| Config Field | Environment Variable | Required | Description |
|---|---|---|---|
| `AuthnType` | `CONJUR_AUTHN_TYPE` | Yes | Must be `"azure"` |
| `ServiceID` | `CONJUR_SERVICE_ID` | Yes | Azure authenticator service ID |
| `JWTHostID` | `CONJUR_AUTHN_JWT_HOST_ID` | Yes | Conjur host ID for the Azure workload |
| `JWTContent` | `CONJUR_AUTHN_JWT_TOKEN` | No | Pre-fetched Azure AD token (fetched from IMDS if empty) |
| `AzureClientID` | `CONJUR_AUTHN_AZURE_CLIENT_ID` | No | Client ID for user-assigned identity |

```go
config.AuthnType = "azure"
config.ServiceID = "prod"
config.JWTHostID = "data/test/azure-apps/myVM"
conjur, err := conjurapi.NewClientFromAzureCredentials(config)
```

#### GCP

Authenticate using a GCP identity token from the metadata server. The token audience is constructed as `conjur/{account}/host/{hostID}`. Unlike AWS IAM and Azure, GCP does **not** require a `ServiceID`.

| Config Field | Environment Variable | Required | Description |
|---|---|---|---|
| `AuthnType` | `CONJUR_AUTHN_TYPE` | Yes | Must be `"gcp"` |
| `JWTHostID` | `CONJUR_AUTHN_JWT_HOST_ID` | Yes | Conjur host ID for the GCP workload |
| `JWTContent` | `CONJUR_AUTHN_JWT_TOKEN` | No | Pre-fetched GCP identity token (fetched from metadata server if empty) |

```go
config.AuthnType = "gcp"
config.JWTHostID = "myapp/gcp-instance"
conjur, err := conjurapi.NewClientFromGCPCredentials(config, "") // "" uses default metadata URL
```

#### Certificate Authentication (authn-cert / mTLS)

You can authenticate using a client certificate and private key via mutual TLS (mTLS).
This method is suitable for workloads that already possess a machine certificate issued
by a trusted CA (e.g., enterprise PKI, SPIFFE/SPIRE).

> [!NOTE]
> Certificate authentication is not supported for Conjur Cloud (Idira Secrets
> Manager, SaaS) directly. It is supported for Conjur Cloud Edge deployments
> and all Idira Secrets Manager, Self-Hosted instances.

> [!WARNING]
> Client certificate files should be created with `0644` permissions, and their
> respective private key files should be created with `0600` permissions.

##### Environment Variables

| Variable | Description |
|---|---|
| `CONJUR_APPLIANCE_URL` | URL of your Conjur self-hosted instance |
| `CONJUR_ACCOUNT` | Conjur account name |
| `CONJUR_AUTHN_CERT_SERVICE_ID` | Service ID of the `authn-cert` authenticator |
| `CONJUR_AUTHN_CERT_FILE` | Path to the PEM-encoded client certificate file |
| `CONJUR_AUTHN_CERT_KEY_FILE` | Path to the PEM-encoded private key file |
| `CONJUR_AUTHN_CERT_HOST_ID` | Conjur host ID (omit for SPIFFE mode) |

##### `.conjurrc` Configuration

Only file-path fields are readable from `.conjurrc`. Inline PEM strings
(`ClientCert` / `ClientCertKey`) cannot be set via `.conjurrc` and must be
supplied through the `Config` struct directly.

| `.conjurrc` key | Corresponding `Config` field | Description |
|---|---|---|
| `client_cert_file` | `ClientCertFile` | Path to the PEM-encoded client certificate |
| `client_cert_key_file` | `ClientCertKeyFile` | Path to the PEM-encoded private key |
| `cert_host_id` | `CertHostID` | Conjur host ID (request mode); omit for SPIFFE mode |

> **Note:** Inline PEM support for `.conjurrc` (`client_cert` / `client_cert_key`) is not
> currently implemented. Use `CONJUR_AUTHN_CERT_FILE` / `CONJUR_AUTHN_CERT_KEY_FILE`
> environment variables or set `ClientCert` / `ClientCertKey` on the `Config` struct.

##### Two operating modes

| Mode | `CertHostID` | How the host is identified |
|---|---|---|
| **Request mode** | Set to the Conjur host path, e.g. `vm-workloads/vm-01` | Included as a path segment in the authenticate URL |
| **SPIFFE mode** | Empty string `""` | Derived by Conjur from the SPIFFE URI SAN in the certificate |

##### Example: Certificate Authentication

```go
package main

import (
    "fmt"
    "log"

    "github.com/cyberark/conjur-api-go/conjurapi"
)

func main() {
    // Certificate and key can be provided as file paths or as inline PEM strings.
    // File paths support transparent rotation: the SDK re-reads the files on each
    // TLS handshake, so replacing the files on disk takes effect without restart.
    config := conjurapi.Config{
        ApplianceURL:      "https://conjur.example.com",
        Account:           "myorg",
        AuthnType:         "cert",
        ServiceID:         "acme-vm",               // authn-cert service ID
        CertHostID:        "vm-workloads/vm-01",    // omit for SPIFFE mode
        ClientCertFile:    "/etc/ssl/client.pem",   // PEM certificate file
        ClientCertKeyFile: "/etc/ssl/client-key.pem", // PEM private key file
    }

    // Or use environment variables with LoadConfig() + NewClientFromEnvironment().

    conjur, err := conjurapi.NewClientFromCertificate(config)
    if err != nil {
        log.Fatalf("Cannot create cert client: %s", err)
    }

    secretValue, err := conjur.RetrieveSecret("prod/database/password")
    if err != nil {
        log.Fatalf("Cannot retrieve secret: %s", err)
    }

    fmt.Printf("%s", string(secretValue))
}
```

##### SPIFFE Workload API authentication

The SPIFFE provider sources the client certificate from the
[SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
instead of a static file or inline PEM. It fetches an X.509-SVID from the SPIRE agent,
caches it until near expiry, and refreshes it transparently.

**Configuration from environment variables (recommended):** When `SPIFFE_ENDPOINT_SOCKET`
is set, `LoadConfig()` wires the provider automatically. No code change is needed.

###### Prerequisites

- A running SPIRE agent with its socket at `SPIFFE_ENDPOINT_SOCKET`
  (e.g. `unix:///var/run/spire-agent/public/api.sock`)
- A Conjur authn-cert webservice configured for SPIFFE mode

###### Additional environment variables

| Variable | Description |
|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | Address of the SPIRE agent socket (e.g. `unix:///var/run/spire-agent/public/api.sock`) |
| `CONJUR_SPIFFE_ID` | SPIFFE ID to select when the Workload API returns multiple SVIDs (e.g. `spiffe://example.org/workload/myapp`). Required when multiple SVIDs are present. |

###### Error conditions

| Condition | Behaviour |
|---|---|
| `SPIFFE_ENDPOINT_SOCKET` path does not exist | Fails immediately, error names the missing path |
| Socket exists but gRPC handshake fails | Fails immediately, error message is distinct from "not found" |
| Workload API returns `codes.Unavailable` | Retries up to 3 times with exponential back-off (500 ms initial delay, 2× multiplier) |
| Workload API returns `codes.PermissionDenied` | Fails immediately, error names the condition without leaking credential material |
| Multiple SVIDs returned and `CONJUR_SPIFFE_ID` is not set | Fails immediately, error lists the available SPIFFE IDs |
| `CONJUR_SPIFFE_ID` set but no matching SVID found | Fails immediately, error lists the available SPIFFE IDs |

###### Example: environment-variable configuration (no code changes needed)

Set these variables in the workload environment:

```sh
SPIFFE_ENDPOINT_SOCKET=unix:///var/run/spire-agent/public/api.sock
CONJUR_AUTHN_CERT_SERVICE_ID=acme-spiffe   # also sets AuthnType=cert implicitly
CONJUR_APPLIANCE_URL=https://conjur.example.com
CONJUR_ACCOUNT=myorg
# Optional: CONJUR_SPIFFE_ID=spiffe://example.org/workload/myapp
```

Then in code:

```go
config, err := conjurapi.LoadConfig()   // picks up SPIFFE_ENDPOINT_SOCKET automatically
if err != nil {
    log.Fatalf("Cannot load config: %s", err)
}
conjur, err := conjurapi.NewClientFromCertificate(config)
if err != nil {
    log.Fatalf("Cannot create SPIFFE client: %s", err)
}
secretValue, err := conjur.RetrieveSecret("prod/database/password")
fmt.Printf("%s", string(secretValue))
```

###### Example: code-based configuration

```go
package main

import (
    "fmt"
    "log"

    "github.com/cyberark/conjur-api-go/conjurapi"
    "github.com/cyberark/conjur-api-go/conjurapi/spiffe"
)

func main() {
    // SPIFFE_ENDPOINT_SOCKET and (optionally) CONJUR_SPIFFE_ID are read from the
    // environment at the time the provider fetches the certificate.
    config := conjurapi.Config{
        ApplianceURL:       "https://conjur.example.com",
        Account:            "myorg",
        AuthnType:          "cert",
        ServiceID:          "acme-spiffe",           // authn-cert service ID
        ClientCertProvider: spiffe.NewProvider(),    // SVID from the Workload API
    }

    conjur, err := conjurapi.NewClientFromCertificate(config)
    if err != nil {
        log.Fatalf("Cannot create SPIFFE client: %s", err)
    }

    secretValue, err := conjur.RetrieveSecret("prod/database/password")
    if err != nil {
        log.Fatalf("Cannot retrieve secret: %s", err)
    }

    fmt.Printf("%s", string(secretValue))
}
```

##### JWT-SVID authentication via the Workload API

Use `spiffe.NewJWTProvider()` to source a JWT-SVID from the SPIFFE Workload API
for Conjur's authn-jwt authenticator. The provider reads the audience from
`CONJUR_JWT_AUDIENCE` at construction time (default: `"conjur"`), fetches a
JWT-SVID from the SPIRE agent, caches it until near expiry, and refreshes it
transparently.

When both `SPIFFE_ENDPOINT_SOCKET` and `CONJUR_AUTHN_JWT_SERVICE_ID` are set and
no static token is configured (`CONJUR_AUTHN_JWT_TOKEN` and `JWT_TOKEN_PATH` are
both unset), `LoadFromEnvironment` (used by `NewClientFromEnvironment`) auto-wires
`JWTProvider` automatically. No code change is required for workloads that read
config from the environment.

###### Prerequisites

- A running SPIRE agent with its socket at `SPIFFE_ENDPOINT_SOCKET`
  (e.g. `unix:///var/run/spire-agent/public/api.sock`)
- A Conjur authn-jwt webservice with `jwks-uri` pointing to the SPIRE OIDC
  discovery provider (e.g. `http://spire-oidc:8085/keys`)
- A Conjur host with annotation `authn-jwt/<service-id>/sub: <spiffe-id>`

###### Additional environment variables

| Variable | Description |
|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | Address of the SPIRE agent socket (e.g. `unix:///var/run/spire-agent/public/api.sock`) |
| `CONJUR_AUTHN_JWT_SERVICE_ID` | Conjur authn-jwt service ID; triggers auto-wire when `SPIFFE_ENDPOINT_SOCKET` is also set |
| `CONJUR_JWT_AUDIENCE` | JWT audience claim to request (default: `"conjur"`). Read once at construction time. |
| `CONJUR_SPIFFE_ID` | SPIFFE ID to select when the Workload API returns multiple SVIDs. Required when multiple SVIDs are present. |

###### Example: explicit JWTProvider wiring

```go
package main

import (
    "fmt"
    "log"

    "github.com/cyberark/conjur-api-go/conjurapi"
    "github.com/cyberark/conjur-api-go/conjurapi/spiffe"
)

func main() {
    // SPIFFE_ENDPOINT_SOCKET is read from the environment.
    // CONJUR_JWT_AUDIENCE defaults to "conjur" when unset.
    config := conjurapi.Config{
        ApplianceURL: "https://conjur.example.com",
        Account:      "myorg",
        AuthnType:    "jwt",
        ServiceID:    "acme-spiffe-jwt",       // authn-jwt service ID
        JWTProvider:  spiffe.NewJWTProvider(), // JWT-SVID from the Workload API
    }

    conjur, err := conjurapi.NewClientFromJwt(config)
    if err != nil {
        log.Fatalf("Cannot create SPIFFE JWT client: %s", err)
    }

    secretValue, err := conjur.RetrieveSecret("prod/database/password")
    if err != nil {
        log.Fatalf("Cannot retrieve secret: %s", err)
    }

    fmt.Printf("%s", string(secretValue))
}
```

###### Example: auto-wire via environment

```bash
export CONJUR_APPLIANCE_URL="https://conjur.example.com"
export CONJUR_ACCOUNT="myorg"
export SPIFFE_ENDPOINT_SOCKET="unix:///run/spire/sockets/agent.sock"
export CONJUR_AUTHN_JWT_SERVICE_ID="acme-spiffe-jwt"
# No CONJUR_AUTHN_JWT_TOKEN or JWT_TOKEN_PATH — JWTProvider is wired automatically.
```

```go
// NewClientFromEnvironment reads SPIFFE env vars and auto-wires JWTProvider.
conjur, err := conjurapi.NewClientFromEnvironment(conjurapi.Config{})
```

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing
guide][contrib].

[contrib]: https://github.com/cyberark/conjur-api-go/blob/main/CONTRIBUTING.md

## License

Copyright (c) 2022-2026 Palo Alto Networks Ltd. All rights reserved.

This repository is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE) for more details.
