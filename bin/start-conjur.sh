#!/bin/bash -ex

. ./utils.sh

trap teardown EXIT

# Type of Conjur to test against, 'all' or 'oss'
export TEST_VERSION="${TEST_VERSION:-all}"
announce "Compose Project Name: $COMPOSE_PROJECT_NAME
     Conjur Test Version: $TEST_VERSION"

main() {
  # If oss only, we don't run v4 tests
  if oss_only; then
      images=("conjur")
  else
      images=("conjur" "cuke-master" )
  fi

  announce "Pulling images..."
  docker-compose -p $COMPOSE_PROJECT_NAME pull ${images[@]} "postgres" "cli5"
  echo "Done!"

  announce "Building images..."
  docker-compose -p $COMPOSE_PROJECT_NAME build ${images[@]} "postgres"
  echo "Done!"

  announce "Starting Conjur environment..."
  export CONJUR_DATA_KEY="$(docker-compose -p $COMPOSE_PROJECT_NAME run -T --no-deps conjur data-key generate)"
  docker-compose -p $COMPOSE_PROJECT_NAME up --no-deps -d ${images[@]} "postgres"
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

    # These variables will be checked for during the go testing
    # For example, see conjurapi/variable_test.go
    vars=(
      'existent-variable-with-defined-value'
      'a/ b/c'
      'myapp-01'
      'alice@devops'
      'prod/aws/db-password'
      'research+development'
      'sales&marketing'
      'onemore'
      'binary'
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
      "$(openssl rand 10)"
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

  # Export values needed for tests to access Conjur instance
  export CONJUR_AUTHN_API_KEY="$api_key"
  export CONJUR_V4_AUTHN_API_KEY="$api_key_v4"
  export CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4"
}

main
