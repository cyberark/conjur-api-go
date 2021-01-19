#!/usr/bin/env bash -e

cd "$(dirname "$0")"

function finish {
  docker-compose -f "../docker-compose.yml" down -v
}
trap finish EXIT

source ./build.sh -d

# When we start the dev container, it mounts the current directory in
# the container. This hides the vendored dependencies that got
# installed during the build, so reinstall them.
exec_on dev go mod download

# Start interactive container
docker exec -it \
  -e CONJUR_AUTHN_API_KEY \
  -e CONJUR_V4_AUTHN_API_KEY \
  -e CONJUR_V4_SSL_CERTIFICATE \
  "$(docker-compose ps -q dev)" /bin/bash
