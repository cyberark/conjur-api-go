#!/bin/bash -e

test_image="test"
while getopts :d opt; do
    case $opt in
        d) test_image="dev";;
       \?) echo "Unknown option -$OPTARG"; exit 1;;
    esac
done

function announce() {
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
    echo -e "$BLUE
    ================================
     ${1}
    ================================
    $NC"
}

export COMPOSE_PROJECT_NAME="conjurapigo_$(openssl rand -hex 3)"
export TEST_VERSION="${TEST_VERSION:-all}"  # Type of Conjur to test against, 'all' or 'oss'
announce "Compose Project Name: $COMPOSE_PROJECT_NAME
      Conjur Test Version: $TEST_VERSION"

exec_on() {
  local container="$1"; shift

  docker exec "$(docker-compose ps -q $container)" "$@"
}

oss_only(){
  [ "$TEST_VERSION" == "oss" ]
}

build() {
  docker-compose build "$test_image"
}

main() {
  # Build test container & start the cluster
  announce "Pulling images..."
  if oss_only; then
      docker-compose pull conjur
  else
      docker-compose pull conjur cuke-master
  fi
  docker-compose build postgres conjur cli5 cuke-master
  echo "Done!"

  announce "Starting Conjur and other images..."
  if oss_only; then
    export CONJUR_DATA_KEY="$(docker-compose run -T --no-deps conjur data-key generate)"
    docker-compose up --no-deps -d postgres conjur
  else
    export CONJUR_DATA_KEY="$(docker-compose run -T --no-deps conjur data-key generate)"
    docker-compose up --no-deps -d postgres conjur cuke-master
  fi
  echo "Done!"

  announce "Waiting for conjur to start..."
  exec_on conjur conjurctl wait
  if ! oss_only; then
    exec_on cuke-master /opt/conjur/evoke/bin/wait_for_conjur
  fi
  echo "Done!"

  api_key=$(exec_on conjur conjurctl role retrieve-key cucumber:user:admin | tr -d '\r')

  if ! oss_only; then
    announce "Running cuke setup..."
    exec_on cuke-master bash -c 'conjur authn login -u admin -p secret'
    exec_on cuke-master conjur user create --as-group security_admin alice
    exec_on cuke-master conjur host create --as-group security_admin bob
    exec_on cuke-master conjur variable create existent-variable-with-undefined-value

    vars=(
      'existent-variable-with-defined-value'
      'a/ b/c'
      'myapp-01'
      'alice@devops'
      'prod/aws/db-password'
      'research+development'
      'sales&marketing'
      'onemore'
    )

    secrets=(
      'existent-variable-defined-value'
      'a/ b/c'
      'these'
      'are'
      'all'
      'secret'
      'strings'
      '{"json": "object"}'
    )

    count=${#vars[@]}
    for ((i=0; i<$count; i++)); do
      id="${vars[$i]}"
      val="${secrets[$i]}"
      exec_on cuke-master conjur variable create "$id"
      exec_on cuke-master conjur variable values add "$id" "$val"
    done

    api_key_v4=$(exec_on cuke-master conjur user rotate_api_key)
    ssl_cert_v4=$(exec_on cuke-master cat /opt/conjur/etc/ssl/ca.pem)

    echo "Done!"
  fi

  export CONJUR_AUTHN_API_KEY="$api_key"
  export CONJUR_V4_AUTHN_API_KEY="$api_key_v4"
  export CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4"

  announce "Building test container ($test_image)..."
  build
}

main
