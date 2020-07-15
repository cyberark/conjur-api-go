#!/bin/bash -ex

function finish {
  docker-compose down -v
}
trap finish EXIT

echo "Running tests"

# Clean then generate output folder locally
rm -rf output
mkdir -p output

source ./_setup.sh

failed() {
  echo "TESTS FAILED"
  exit 1
}

# Execute tests
CONJUR_AUTHN_API_KEY="$api_key" \
  CONJUR_V4_AUTHN_API_KEY="$api_key_v4" \
  CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4" \
  docker-compose run test \
    bash -c 'set -o pipefail;
             echo "Running tests...";
             go test -coverprofile="output/c.out" -v ./... | tee output/junit.output;
             exit_code=$?;
             echo "Tests finished - aggregating results...";
             cat output/junit.output | go-junit-report > output/junit.xml;
             gocov convert ./output/c.out | gocov-xml > output/coverage.xml;
             [ "$exit_code" -eq 0 ]' || failed
