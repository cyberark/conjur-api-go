#!/usr/bin/env bash -ex

cd "$(dirname "$0")"
. ./utils.sh

source ./start-conjur.sh

docker compose build dev
docker compose up --no-deps -d dev

# When we start the dev container, it mounts the top-level directory in
# the container. This excludes the vendored dependencies that got
# installed during the build, so reinstall them.
exec_on dev go mod download

# Start interactive container
docker exec -it \
  -e CONJUR_AUTHN_API_KEY \
  "$(docker compose ps -q dev)" /bin/bash
