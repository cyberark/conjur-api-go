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
docker-compose pull postgres conjur
docker-compose build --pull
docker-compose up -d

# Delay to allow time for Possum to come up
# TODO: remove this once we have HEALTHCHECK in place
docker-compose exec -T test ./wait_for_server.sh

api_key=$(docker-compose exec -T conjur rails r "print Credentials['cucumber:user:admin'].api_key")

# Execute tests
docker-compose exec -T test env \
    CONJUR_AUTHN_API_KEY=$api_key \
    bash -c 'go test -v "$(go list ./... | grep -v /vendor/)" | tee output/junit.output && cat output/junit.output | go-junit-report > output/junit.xml'
