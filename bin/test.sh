#!/bin/bash -e

cd "$(dirname "$0")"
source ./utils.sh

trap teardown EXIT

# unique for pipeline; repeatable & meaningful for dev
PROJECT_SUFFIX="$(openssl rand -hex 3)"

# To selectively choose packages and tests, export these envs before call:
#   API_PKGS   such as "./..." or "./conjurapi"
#              will be passed like 'go test -v <PKGS>'
#   API_TESTS  such as "TestClient_LoadPolicy"
#              will be used like 'go test -run <TESTS>'

# default to no tests specified, all packages
PKGS="-v ./..."
TESTS=""
if [ "$API_PKGS" != "" ]; then
    PKGS="-v ${API_PKGS}"
fi
if [ "$API_TESTS" != "" ]; then
    TESTS="-run ${API_TESTS}"
    PROJECT_SUFFIX=$(project_nameable "$API_TESTS")
fi

export COMPOSE_PROJECT_NAME="conjurapigo_${PROJECT_SUFFIX}"
export GO_VERSION="${1:-"1.23"}"
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

  # We are using package list mode of 'go test'
  # note: the expression must be eval'ed before passing to docker
  export TEST_PKGS="$PKGS $TESTS"

  announce "Running tests for Go version: $GO_VERSION...";
  echo "Package and test selection: $TEST_PKGS"

  docker compose run \
  --rm \
  --no-deps \
  -e CONJUR_AUTHN_API_KEY \
  -e GO_VERSION \
  -e PUBLIC_KEYS \
  -e JWT \
  -e TEST_PKGS \
  "test-$GO_VERSION" bash -c 'set -o pipefail;
           echo "Go version: $(go version)"
           output_dir="./output/$GO_VERSION"
           go test -coverprofile="$output_dir/c.out" $TEST_PKGS | tee "$output_dir/junit.output";
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
  export IDENTITY_TOKEN=$INFRAPOOL_IDENTITY_TOKEN

  output_dir="../output/cloud"
  mkdir -p $output_dir

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
    -e IDENTITY_TOKEN \
    -v "$(pwd)/../output:/conjur-api-go/output" \
    "test-$GO_VERSION" bash -c 'set -xo pipefail;
            output_dir="./output/cloud"
            go test -coverprofile="$output_dir/c.out" -v ./... | tee "$output_dir/junit.output";
            exit_code=$?;
            echo "Tests finished - aggregating results...";
            cat "$output_dir/junit.output" | go-junit-report > "$output_dir/junit.xml";
            gocov convert "$output_dir/c.out" | gocov-xml > "$output_dir/coverage.xml";
            gocovmerge "./output/1.23/c.out" "$output_dir/c.out" > "$output_dir/merged-coverage.out";
            gocov convert "$output_dir/merged-coverage.out" | gocov-xml > "$output_dir/merged-coverage.xml";
            [ "$exit_code" -eq 0 ]' || failed
fi
