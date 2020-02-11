# conjurapi

Programmatic Golang access to the Conjur API.

# Installation

```
$ go get github.com/cyberark/conjur-api-go/conjurapi
```

# Quick start

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
# Usage

Connecting to Conjur is a two-step process:

* **Configuration** Instruct the API where to find the Conjur endpoint and how to secure the connection.
* **Authentication** Provide the API with credentials that it can use to authenticate.

# Development (docker-compose)

Kick off your TDD (i.e. goconvey powered) development environment as follows:

```bash
# goconvey will run as a background process
./dev
```

Visit localhost:8080 to see the test results in real time.

# Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

This repository is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE) for more details.
