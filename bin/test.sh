#!/bin/bash -e

top_level_path="$(pwd)"
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
export GO_VERSION="${1:-"1.24"}"
export REGISTRY_URL="${2:-docker.io}"
export TEST_AWS="${INFRAPOOL_TEST_AWS:-false}"
export TEST_AZURE="${INFRAPOOL_TEST_AZURE:-false}"
export TEST_GCP="${INFRAPOOL_TEST_GCP:-false}"

if [[ "$TEST_GCP" == "true" ]]; then
  export GCP_CTX_DIR="${3:-gcp}"
  GCP_PROJECT_ID=""
  GCP_ID_TOKEN=""
  if [[ -f "$top_level_path/$GCP_CTX_DIR/project-id" ]]; then
    read -r GCP_PROJECT_ID < "$top_level_path/$GCP_CTX_DIR/project-id"
  fi
  if [[ -f "$top_level_path/$GCP_CTX_DIR/token" ]]; then
    read -r GCP_ID_TOKEN < "$top_level_path/$GCP_CTX_DIR/token"
  fi
  if [[ -z "$GCP_PROJECT_ID" || -z "$GCP_ID_TOKEN" ]]; then
    echo "GCP_PROJECT_ID and GCP_ID_TOKEN must be set to run GCP tests"
    failed
  fi
  export GCP_PROJECT_ID
  export GCP_ID_TOKEN
fi

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
  -e TEST_AWS \
  -e TEST_AZURE \
  -e AZURE_SUBSCRIPTION_ID \
  -e AZURE_RESOURCE_GROUP \
  -e TEST_GCP \
  -e GCP_PROJECT_ID \
  -e GCP_ID_TOKEN \
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
  export CONJUR_APPLIANCE_URL="$INFRAPOOL_CONJUR_APPLIANCE_URL/api"
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
  # NOTE: Skipping hostfactory token tests as hostfactory endpoints seem to be disabled by default now
  docker run \
    -e CONJUR_APPLIANCE_URL \
    -e CONJUR_ACCOUNT \
    -e CONJUR_AUTHN_LOGIN \
    -e CONJUR_AUTHN_TOKEN \
    -e TEST_AWS \
    -e TEST_AZURE \
    -e AZURE_SUBSCRIPTION_ID \
    -e AZURE_RESOURCE_GROUP \
    -e TEST_GCP \
    -e GCP_PROJECT_ID \
    -e GCP_ID_TOKEN \
    -e PUBLIC_KEYS \
    -e JWT \
    -e IDENTITY_TOKEN \
    -v "$(pwd)/../output:/conjur-api-go/output" \
    "test-$GO_VERSION" bash -c 'set -xo pipefail;
            output_dir="./output/cloud"
            go test -coverprofile="$output_dir/c.out" -skip "TestClient_Token" -v ./... | tee "$output_dir/junit.output";
            exit_code=$?;
            echo "Tests finished - aggregating results...";
            cat "$output_dir/junit.output" | go-junit-report > "$output_dir/junit.xml";
            gocov convert "$output_dir/c.out" | gocov-xml > "$output_dir/coverage.xml";
            gocovmerge "./output/1.24/c.out" "$output_dir/c.out" > "$output_dir/merged-coverage.out";
            gocov convert "$output_dir/merged-coverage.out" | gocov-xml > "$output_dir/merged-coverage.xml";
            [ "$exit_code" -eq 0 ]' || failed
fi
