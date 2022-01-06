#!/bin/bash -e

cd "$(dirname "$0")"
. ./utils.sh

export COMPOSE_PROJECT_NAME="conjurapigo_$(openssl rand -hex 3)"
export GO_VERSION="${1:-"1.16"}"

# Spin up Conjur environment
source ./start-conjur.sh

announce "Building test containers..."
docker-compose build "test-$GO_VERSION"
echo "Done!"

# generate output folder locally, if needed
output_dir="../output/$GO_VERSION"
mkdir -p $output_dir

failed() {
  announce "TESTS FAILED"
  docker logs "$(docker-compose ps -q cuke-master)"
  exit 1
}

# Golang container version to use: `1.16` or `1.17`
announce "Running tests for Go version: $GO_VERSION...";
docker-compose run \
  -e CONJUR_AUTHN_API_KEY \
  -e CONJUR_V4_AUTHN_API_KEY \
  -e CONJUR_V4_SSL_CERTIFICATE \
  -e GO_VERSION \
  "test-$GO_VERSION" bash -c 'set -o pipefail;
           echo "Go version: $(go version)"
           output_dir="./output/$GO_VERSION"
           go test -coverprofile="$output_dir/c.out" -v ./... | tee "$output_dir/junit.output";
           exit_code=$?;
           echo "Tests finished - aggregating results...";
           cat "$output_dir/junit.output" | go-junit-report > "$output_dir/junit.xml";
           gocov convert "$output_dir/c.out" | gocov-xml > "$output_dir/coverage.xml";
           [ "$exit_code" -eq 0 ]' || failed
