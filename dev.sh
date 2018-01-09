#!/usr/bin/env bash -ex

function finish {
  docker-compose down -v
}
trap finish EXIT

source ./_setup.sh

# Run development environment
docker-compose exec test env \
    CONJUR_AUTHN_API_KEY="$api_key" \
    CONJUR_V4_AUTHN_API_KEY="$api_key_v4" \
    CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4" \
    bash -c "./convey.sh& bash"
