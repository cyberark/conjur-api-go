#!/usr/bin/env bash

export compose_file="../docker-compose.yml"

function announce() {
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
    echo -e "$BLUE
    ================================
     ${1}
    ================================
    $NC"
}

exec_on() {
  local container="$1"; shift

  docker exec "$(docker-compose -p $COMPOSE_PROJECT_NAME ps -q $container)" "$@"
}

function teardown() {
  docker-compose -p $COMPOSE_PROJECT_NAME down -v
}

function announce_failure() {
  announce "TESTS FAILED"
  docker logs "$(docker-compose -p ${COMPOSE_PROJECT_NAME} ps -q conjur-${CONJUR_EDITION})"
  exit 1
}
