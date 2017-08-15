# conjurapi

Programmatic Golang access to the Conjur API.

# Installation

Clone or use Golang dependency manager of choice

# Usage

Connecting to Conjur is a two-step process:

* **Configuration** Instruct the API where to find the Conjur endpoint and how to secure the connection.
* **Authentication** Provide the API with credentials that it can use to authenticate.

## Configuration

This client does not use a configuration pattern to connect to Conjur.
Configuration must be specified explicitly.

You can load the Conjur configuration from your environment using the following Go code:

```go
import "github.com/conjurinc/api-go/conjurapi"

config := conjurapi.Config{
    Account:      os.Getenv("CONJUR_ACCOUNT"),
    ApplianceURL: os.Getenv("CONJUR_APPLIANCE_URL"),
}
        
conjur, err := conjurapi.NewClientFromKey(
    config: config, 
    Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
    APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
)
```

## Read secret

Authenticated clients are able to retrieve secrets:

```go
secretValue, err := conjur.RetrieveSecret(variableIdentifier)
if err != nil {
// error handling
}
// do something with the secretValue
```

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
