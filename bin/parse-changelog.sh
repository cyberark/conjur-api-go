#!/bin/bash -ex

cd "$(dirname "$0")"

docker run --rm \
  -v "$(pwd)/..:/work" \
  -w "/work" \
  ruby:2.5 bash -ec "
    gem install -N parse_a_changelog
    parse ./CHANGELOG.md
  "
