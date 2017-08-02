#!/usr/bin/env bash

docker run -it --rm -p 8080:8080 -v "$(pwd)":/go/src/github.com/conjurinc/api-go --name conjur-api-go conjur-api-go

