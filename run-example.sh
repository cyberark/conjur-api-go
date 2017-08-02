#!/usr/bin/env bash

export CONJUR_APPLIANCE_URL=https://eval.conjur.org
export CONJUR_ACCOUNT="kumbirai.tanekha@cyberark.com"
export CONJUR_LOGIN="host/myapp-01"
export CONJUR_API_KEY="56tvba3t686x23wdmc9795dfck1z17992yhddhnbq2dmq23ph1b"

go build
go install
cd example
go run $(ls -1 *.go | grep -v _test.go) $*
