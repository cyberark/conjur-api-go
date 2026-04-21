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
  output_dir="../output/${GO_VERSION}"

  # Always capture OSS Conjur logs when available.
  docker compose logs conjur > "$output_dir/conjur-logs.txt" 2>&1 || true

  if [[ "${TEST_CERT:-false}" == "true" ]]; then
    # In cert profile runs, authn-cert traffic goes to the Enterprise appliance
    docker compose --profile cert logs conjur-leader > "$output_dir/conjur-leader-logs.txt" 2>&1 || true
    docker compose --profile cert down -v --remove-orphans
  else
    docker compose down -v --remove-orphans
  fi
  unset API_PKGS
  unset API_TESTS
}

failed() {
  announce "TESTS FAILED"
  # docker compose logs conjur || true
  exit 1
}

# Docker program name rules: must consist only of lowercase alphanumeric characters,
# hyphens, and underscores as well as start with a letter or number
function project_nameable() {
  local split=$(echo "$1" | tr ',.@/' '-')
  local lower=$(echo "$split" | tr '[:upper:]' '[:lower:]')
  local shrnk=$(echo "$lower" | tr -d 'aeiou')
  echo "$shrnk"
}

# Starts a temporary JWT issuer service and exports the public keys and JWT token
# NOTE: We curl from a container in the compose network so we don't have to map a
# host port - otherwise a port collision may occur when running tests in parallel
function init_jwt_server() {
  pushd ..
  docker compose up -d mock-jwt-server
  while true; do
    export JWT=$(docker compose run -T --rm --no-deps --entrypoint /bin/bash conjur -c "curl http://mock-jwt-server:8080/token" | jq -r .token)
    if [[ -n "$JWT" ]]; then
      break
    fi
    echo "Waiting for mock JWT server to be ready..."
    sleep 1
  done
  export PUBLIC_KEYS=$(docker compose run -T --rm --no-deps --entrypoint /bin/bash conjur -c "curl http://mock-jwt-server:8080/.well-known/jwks.json")
  docker compose down mock-jwt-server
  popd
}
