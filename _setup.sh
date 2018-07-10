#!/bin/bash -ex

exec_on() {
  local container="$1"; shift

  docker exec "$(docker-compose ps -q $container)" "$@"
}

# Build test container & start the cluster
docker-compose pull conjur cuke-master
docker-compose build

CONJUR_DATA_KEY="$(docker-compose run -T --no-deps conjur data-key generate)" \
  docker-compose up --no-deps -d postgres conjur cuke-master
exec_on conjur conjurctl wait
exec_on cuke-master /opt/conjur/evoke/bin/wait_for_conjur

api_key=$(exec_on conjur conjurctl role retrieve-key cucumber:user:admin | tr -d '\r')

exec_on cuke-master bash -c 'conjur authn login -u admin -p secret'
exec_on cuke-master conjur user create --as-group security_admin alice
exec_on cuke-master conjur variable create existent-variable-with-undefined-value
exec_on cuke-master conjur variable create existent-variable-with-defined-value
exec_on cuke-master conjur variable values add existent-variable-with-defined-value existent-variable-defined-value

api_key_v4=$(exec_on cuke-master conjur user rotate_api_key)
ssl_cert_v4=$(exec_on cuke-master cat /opt/conjur/etc/ssl/ca.pem)
