#!/usr/bin/env bash -ex

# This script's not idempotent, so shut everything down before trying
# to bring it all up again.
docker-compose down

source ./_setup.sh

# Run development environment
CONJUR_AUTHN_API_KEY="$api_key" \
  CONJUR_V4_AUTHN_API_KEY="$api_key_v4" \
  CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4" \
  docker-compose run --no-deps -d dev

# When we start the dev container, it mounts the current directory in
# the container. This hides the vendored dependencies that got
# installed during the build, so reinstall them.
exec_on dev go mod download
