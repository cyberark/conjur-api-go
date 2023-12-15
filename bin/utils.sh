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
