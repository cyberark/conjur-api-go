#!/usr/bin/env bash

cd "$(dirname "$0")"

goconvey -host 0.0.0.0 ../conjurapi
