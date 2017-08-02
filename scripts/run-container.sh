#!/usr/bin/env bash

docker run -it --rm -v "$(pwd)":/go/src/github.com/conjurinc/api-go --name conjur-api-go conjur-api-go

