#!/bin/bash -ex

. ./utils.sh

trap teardown ERR

announce "Compose Project Name: $COMPOSE_PROJECT_NAME"

main() {
  announce "Pulling images..."
  docker compose pull "conjur" "postgres" "cli5"
  echo "Done!"

  announce "Building images..."
  docker compose build "conjur" "postgres"
  echo "Done!"

  announce "Starting Conjur environment..."
  export CONJUR_DATA_KEY="$(docker compose run -T --no-deps conjur data-key generate)"
  docker compose up --no-deps -d "conjur" "postgres"
  echo "Done!"

  announce "Waiting for conjur to start..."
  exec_on conjur conjurctl wait

  echo "Done!"

  api_key=$(exec_on conjur conjurctl role retrieve-key cucumber:user:admin | tr -d '\r')

  # Export values needed for tests to access Conjur instance
  export CONJUR_AUTHN_API_KEY="$api_key"
}

main
