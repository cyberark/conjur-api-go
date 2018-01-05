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
)

func Main() {
    variableIdentifier := "db/secret"
    
    config := conjurapi.LoadConfig()
            
    conjur, err := conjurapi.NewClientFromKey(
        config: config,
        login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
        aPIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
    )
    if err != nil {
        panic(err)
    }
    
    secretResponse, err := conjur.RetrieveSecret(variableIdentifier)
    if err != nil {
        panic(err)
    }
    secretValue, err := conjur.ReadResponseBody(secretResponse)
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

# License

Copyright 2016-2017 CyberArk

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
