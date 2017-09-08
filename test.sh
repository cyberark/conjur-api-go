#!/bin/bash -ex

function finish {
  docker-compose down -v
}
trap finish EXIT

echo "Running tests"

# Clean then generate output folder locally
rm -rf output
mkdir -p output

# Build test container & start the cluster
docker-compose pull postgres conjur cuke-master
docker-compose build --pull
docker-compose up -d

# Delay to allow time for Possum to come up
# TODO: remove this once we have HEALTHCHECK in place
docker-compose exec -T test ./wait_for_server.sh

api_key=$(docker-compose exec -T conjur rails r "print Credentials['cucumber:user:admin'].api_key")

docker-compose exec -T cuke-master bash -c "conjur authn login -u admin -p secret"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-undefined-value"
docker-compose exec -T cuke-master bash -c "conjur variable create existent-variable-with-defined-value"
docker-compose exec -T cuke-master bash -c "conjur variable values add existent-variable-with-defined-value existent-variable-defined-value"

api_key_v4=$(docker-compose exec -T cuke-master bash -c "conjur user rotate_api_key")
ssl_cert_v4=$(docker-compose exec -T cuke-master bash -c "cat /opt/conjur/etc/ssl/ca.pem")

# Execute tests
docker-compose exec -T test env \
    CONJUR_AUTHN_API_KEY="$api_key" \
    CONJUR_V4_AUTHN_API_KEY="$api_key_v4" \
    CONJUR_V4_SSL_CERTIFICATE="$ssl_cert_v4" \
    bash -c 'go test -v $(go list ./... | grep -v /vendor/) | tee output/junit.output && cat output/junit.output | go-junit-report > output/junit.xml'
