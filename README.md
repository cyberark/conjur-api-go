# conjurapi

Programmatic Golang access to the Conjur API.

## Certification level
![](https://img.shields.io/badge/Certification%20Level-Community-28A745?link=https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

This repo is a **Community** level project. It's a community contributed project that **is not reviewed or supported
by CyberArk**. For more detailed information on our certification levels, see [our community guidelines](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md#community).

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

    - 1.23
    - 1.24

## Installation

```
$ go get github.com/cyberark/conjur-api-go/conjurapi
```

## Quick start

Fetching a Secret, for example:

Suppose there exists a variable `db/secret` with secret value `fde5c4a45ce573f9768987cd`

Create a go program using `conjur-api-go` to fetch the secret value:

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

Connecting to Conjur is a two-step process:

* **Configuration** Instruct the API where to find the Conjur endpoint and how to secure the connection.
* **Authentication** Provide the API with credentials that it can use to authenticate.

### Authenticating with authn-jwt via Environment Variables

#### Example Code

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cyberark/conjur-api-go/conjurapi"
)

// Environment variables to define:
// CONJUR_APPLIANCE_URL, CONJUR_ACCOUNT, CONJUR_AUTHN_JWT_SERVICE_ID,
// CONJUR_AUTHN_JWT_TOKEN, CONJUR_SECRET_ID

func checkEnvironmentVariables() error {
	// Check for environment variables and error if one is missing.
	variables := []string{
		"CONJUR_APPLIANCE_URL",
		"CONJUR_ACCOUNT",
		"CONJUR_AUTHN_JWT_SERVICE_ID",
		"CONJUR_AUTHN_JWT_TOKEN",
		"CONJUR_SECRET_ID",
	}

	for _, variable := range variables {
		if os.Getenv(variable) == "" {
			return fmt.Errorf("Environment variable %s is not set", variable)
		}
	}

	return nil
}

func main() {

	// Check for environment variables and error if one is missing.
	err := checkEnvironmentVariables()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Defining secret ID to retrieve, as per 12 factor
	// this is being accomplished via env variables.
	variableIdentifier := os.Getenv("CONJUR_SECRET_ID")

	// Loading configuration via defined Env vars:
	// CONJUR_APPLIANCE & CONJUR_ACCOUNT
	config, err := conjurapi.LoadConfig()
	if err != nil {
		log.Fatalf("Cannot load configuration. %s", err)
	}

	// Create a new Conjur client using environment variables
	conjur, err := conjurapi.NewClientFromEnvironment(config)
	if err != nil {
		log.Fatalf("Cannot create new client from environment variables. %s", err)
	}

	// Retrieve the secret value from Conjur
	secretValue, err := conjur.RetrieveSecret(variableIdentifier)
	if err != nil {
		log.Fatalf("Cannot retrieve secret value for %s. %s", variableIdentifier, err)
	}

	// Print the secret value to stdout
	fmt.Printf("%s", string(secretValue))
}
```

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing
guide][contrib].

[contrib]: https://github.com/cyberark/conjur-api-go/blob/main/CONTRIBUTING.md

## License

Copyright (c) 2022-2024 CyberArk Software Ltd. All rights reserved.

This repository is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE) for more details.
