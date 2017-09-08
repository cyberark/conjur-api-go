#!/usr/bin/env bash -ex

function finish {
  docker-compose down -v
}
trap finish EXIT

docker-compose pull postgres conjur
docker-compose build --pull
docker-compose up -d
docker-compose exec -T test ./wait_for_server.sh

api_key=$(docker-compose exec -T conjur rails r "print Credentials['cucumber:user:admin'].api_key")

docker-compose exec -T cuke-master bash -c "conjur authn login -u admin -p secret"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-undefined-value"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-defined-value"
docker-compose exec -T cuke-master bash -c "conjur variable values add existent-variable-with-defined-value existent-variable-defined-value"

api_key_v4=$(docker-compose exec -T cuke-master bash -c "conjur user rotate_api_key")
ssl_cert_v4=$(docker-compose exec -T cuke-master bash -c "cat /opt/conjur/etc/ssl/ca.pem")

# Run development environment
docker-compose exec test env \
    CONJUR_AUTHN_API_KEY="$api_key" \
    CONJUR_V4_AUTHN_API_KEY="$api_key_v4" \
    CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4" \
    bash -c "./convey.sh& bash"
