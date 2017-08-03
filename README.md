# conjurapi

Programmatic Golang access to the Conjur API.

# Installation

Clone or use Golang dependency manage of choice

# Usage

Connecting to Conjur is a two-step process:

* **Configuration** Instruct the API where to find the Conjur endpoint and how to secure the connection.
* **Authentication** Provide the API with credentials that it can use to authenticate.

## Configuration

This client does not use a configuration pattern to connect to Conjur.
Configuration must be specified explicitly.

You can load the Conjur configuration from your environemnt using the following Go code:

```go
import "github.com/conjurinc/api-go/conjurapi"

config := conjurapi.Config{
            Account:      os.Getenv("CONJUR_ACCOUNT"),
            APIKey:       os.Getenv("CONJUR_API_KEY"),
            ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
            Username:     "admin",
        }
        
conjur := conjurapi.NewClient(config)
```

## Read secret

Authenticated clients are able to retrieves variables:

```go
secretValue, err := conjur.RetrieveVariable(variableName)
```

# Development (docker-compose)

Kick off your TDD (i.e. goconvey powered) development environment as follows:

```bash
# goconvey will run as a background process
./run-dev
```

Visit localhost:8080 to see the test results in real time.

# Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
