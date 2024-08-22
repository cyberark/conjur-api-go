#!/bin/bash -e

cd "$(dirname "$0")"
. ./utils.sh

trap teardown EXIT

export COMPOSE_PROJECT_NAME="conjurapigo_$(openssl rand -hex 3)"
export GO_VERSION="${1:-"1.22"}"
export REGISTRY_URL="${2:-docker.io}"
echo "REGISTRY_URL is set to: $REGISTRY_URL"

init_jwt_server

if [ -z "$INFRAPOOL_TEST_CLOUD" ]; then
  # Spin up Conjur environment
  source ./start-conjur.sh

  announce "Building test containers..."
  docker compose build "test-$GO_VERSION"
  echo "Done!"

  # generate output folder locally, if needed
  output_dir="../output/$GO_VERSION"
  mkdir -p $output_dir

  announce "Running tests for Go version: $GO_VERSION...";

  docker compose run \
  --no-deps \
  -e CONJUR_AUTHN_API_KEY \
  -e GO_VERSION \
  -e PUBLIC_KEYS \
  -e JWT \
  "test-$GO_VERSION" bash -c 'set -o pipefail;
           echo "Go version: $(go version)"
           output_dir="./output/$GO_VERSION"
           go test -coverprofile="$output_dir/c.out" -v ./... | tee "$output_dir/junit.output";
           exit_code=$?;
           echo "Tests finished - aggregating results...";
           cat "$output_dir/junit.output" | go-junit-report > "$output_dir/junit.xml";
           gocov convert "$output_dir/c.out" | gocov-xml > "$output_dir/coverage.xml";
           [ "$exit_code" -eq 0 ]' || failed
else
  # Export INFRAPOOL env vars for Cloud tests
  export CONJUR_APPLIANCE_URL=$INFRAPOOL_CONJUR_APPLIANCE_URL
  export CONJUR_ACCOUNT=conjur
  export CONJUR_AUTHN_LOGIN=$INFRAPOOL_CONJUR_AUTHN_LOGIN
  export CONJUR_AUTHN_TOKEN=$(echo "$INFRAPOOL_CONJUR_AUTHN_TOKEN" | base64 --decode)

  # Tests incompatible with Conjur Cloud which should be passed to the -skip flag
  incompatible_tests=(
    # Temporarily skipping due to recent breaking API change:
    "TestClient_LoadPolicy/A_policy_is_successfully_validated"
    "TestClient_LoadPolicy/A_policy_is_not_successfully_validated"
    "TestClient_FetchPolicy"
  )
  export INCOMPATIBLE_TESTS=$(IFS='|'; echo "${incompatible_tests[*]}")

  docker build \
    --build-arg FROM_IMAGE="golang:$GO_VERSION" \
    -t "test-$GO_VERSION" ..
  
  announce "Running Conjur Cloud tests for Go version: $GO_VERSION...";
  docker run \
    -e CONJUR_APPLIANCE_URL \
    -e CONJUR_ACCOUNT \
    -e CONJUR_AUTHN_LOGIN \
    -e CONJUR_AUTHN_TOKEN \
    -e PUBLIC_KEYS \
    -e JWT \
    -e INCOMPATIBLE_TESTS \
    "test-$GO_VERSION" bash -c 'set -o pipefail;
            go test -skip "$INCOMPATIBLE_TESTS" -v ./...'
fi
