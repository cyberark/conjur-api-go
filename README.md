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

- 1.25
- 1.26

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

The Conjur Go API supports three credential storage options, configurable via the `CredentialStorage` field in the `Config` struct:

#### Storage Options

- **`conjurapi.CredentialStorageKeyring`** - Stores credentials in the system keyring (default when available). This is the most secure option for desktop environments.
- **`conjurapi.CredentialStorageFile`** - Stores credentials in a `.netrc` file (default when keyring is not available). The `.netrc` file location can be customized using the `NetRCPath` config field.
- **`conjurapi.CredentialStorageNone`** - Does not store credentials. **Use this option in environments where there are no file permissions to create a `.netrc` file**, such as restricted containers, read-only filesystems, or ephemeral compute instances.

> **Note:** If no credential storage is specified, the API will automatically select `CredentialStorageKeyring` if available, otherwise it will default to `CredentialStorageFile`.

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
| `SSLCertPath` | `CONJUR_CERT_FILE` | No | Path to Conjur SSL certificate |
| `SSLCert` | `CONJUR_SSL_CERTIFICATE` | No | Conjur SSL certificate content |

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

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing
guide][contrib].

[contrib]: https://github.com/cyberark/conjur-api-go/blob/main/CONTRIBUTING.md

## License

Copyright (c) 2022-2026 Palo Alto Networks Ltd. All rights reserved.

This repository is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE) for more details.
