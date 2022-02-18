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

  docker exec "$(docker-compose ps -q $container)" "$@"
}

oss_only(){
  [ "$TEST_VERSION" == "oss" ]
}

function teardown {
  docker-compose down -v
}
