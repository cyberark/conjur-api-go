#!/bin/bash -e

cd "$(dirname "$0")"

function finish {
  docker-compose down -v
}
trap finish EXIT

source ./build.sh

echo "Running tests"

# Clean then generate output folder locally
rm -rf "../output"
mkdir -p "../output"

failed() {
  echo "TESTS FAILED"
  exit 1
}

# Execute tests
docker-compose run \
  -e CONJUR_AUTHN_API_KEY \
  -e CONJUR_V4_AUTHN_API_KEY \
  -e CONJUR_V4_SSL_CERTIFICATE \
  test bash -c 'set -o pipefail;
           echo "Running tests...";
           go test -coverprofile="output/c.out" -v ./... | tee output/junit.output;
           exit_code=$?;
           echo "Tests finished - aggregating results...";
           cat output/junit.output | go-junit-report > output/junit.xml;
           gocov convert ./output/c.out | gocov-xml > output/coverage.xml;
           [ "$exit_code" -eq 0 ]' || failed
