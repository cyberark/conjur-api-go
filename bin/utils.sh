#!/usr/bin/env bash

export compose_file="../docker-compose.yml"

function announce() {
    echo "
    ================================
     ${1}
    ================================
    "
}

exec_on() {
  local container="$1"; shift

  docker exec "$(docker compose ps -q $container)" "$@"
}

function teardown {
  docker compose down -v
}

failed() {
  announce "TESTS FAILED"
  exit 1
}

# Starts a temporary JWT issuer service and exports the public keys and JWT token
# NOTE: We curl from a container in the compose network so we don't have to map a
# host port - otherwise a port collision may occur when running tests in parallel
function init_jwt_server() {
  docker compose up -d jwt-server
  export PUBLIC_KEYS=$(docker compose run -T --no-deps --entrypoint /bin/bash conjur -c "curl http://jwt-server:8008/.well-known/jwks.json")
  export JWT=$(docker compose run -T --no-deps --entrypoint /bin/bash conjur -c "curl -X POST http://jwt-server:8008/token | jq -r .access_token")
  docker compose down jwt-server
}
