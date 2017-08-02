# api-go

Conjur API for Golang.

## Install

Clone or use Golang dependency manage of choice

## Usage

Provide a configuration to start a new instance of the api client -> Client authenticates using configuration -> Authenticated client retrieves variables

```
import "github.com/conjurinc/api-go"

conjur = conjurapi.NewClient(config)
variableValue, err := conjur.RetrieveVariable(variableName)
```

## Configuration

This client does not use a configuration pattern to connect to Conjur.
Configuration must be specified explicitly.

## Development (Docker)

Build and run the development environment as follows:

```
./scripts/build-container
./scripts/run-container
```

An executable example project is available at `./example`. The bash script `./run-example` is useful for testing the package as an import to the example project. Modify `./example/main.go` to suite your experimental needs.
