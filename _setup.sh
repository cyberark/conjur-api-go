#!/bin/bash -ex

# Build test container & start the cluster
docker-compose pull postgres conjur cuke-master
docker-compose build --pull
docker-compose up -d
docker-compose exec -T test ./wait_for_server.sh

api_key=$(docker-compose exec -T conjur conjurctl role retrieve-key cucumber:user:admin | tr -d '\r')

docker-compose exec -T cuke-master bash -c "conjur authn login -u admin -p secret"
docker-compose exec -T cuke-master bash -c "conjur user create --as-group security_admin alice"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-undefined-value"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-defined-value"
docker-compose exec -T cuke-master bash -c "conjur variable values add existent-variable-with-defined-value existent-variable-defined-value"

api_key_v4=$(docker-compose exec -T cuke-master bash -c "conjur user rotate_api_key")
ssl_cert_v4=$(docker-compose exec -T cuke-master bash -c "cat /opt/conjur/etc/ssl/ca.pem")
