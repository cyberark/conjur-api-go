#!/bin/bash -e
# Starts the Conjur Enterprise appliance (the "cert" compose profile) and
# configures it as a leader. Sourced by test.sh (TEST_ENTERPRISE=true) and
# setup-cert-auth.sh (TEST_CERT=true); safe to source more than once.
#
# Exports:
#   CONJUR_CERT_APPLIANCE_URL   - HTTPS URL of the enterprise appliance
#   CONJUR_CERT_AUTHN_API_KEY   - admin API key for that appliance
#   CONJUR_CERT_SSL_CERTIFICATE - PEM of the appliance's self-signed TLS cert

cd "$(dirname "${BASH_SOURCE[0]}")"

. ./utils.sh

# When run standalone (not sourced from test.sh), set a default project name.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conjurapigo_enterprise}"

# Default admin password for the enterprise appliance. Override by setting
# CONJUR_ADMIN_PASSWORD before invoking this script.
export CONJUR_ADMIN_PASSWORD="${CONJUR_ADMIN_PASSWORD:-MySecretP@ss1}"

function start_conjur_appliance() {
  announce "Pulling Conjur Enterprise appliance image..."
  docker compose --profile cert pull conjur-leader
  echo "Done!"

  announce "Starting Conjur Enterprise appliance..."
  # The appliance image is self-contained (embedded postgres); no separate DB needed.
  docker compose --profile cert up --no-deps -d conjur-leader

  # Wait for the container process to be exec-able before running evoke.
  announce "Waiting for enterprise appliance container to start..."
  local timeout=60
  local elapsed=0
  until docker compose --profile cert exec -T conjur-leader true 2>/dev/null; do
    if (( elapsed >= timeout )); then
      echo "Timed out waiting for conjur-leader container to be exec-able"
      exit 1
    fi
    sleep 2
    (( elapsed += 2 ))
  done

  announce "Configuring Conjur Enterprise master..."
  # evoke configure master initialises the account and generates the self-signed
  # TLS certificate for the appliance hostname.
  docker compose --profile cert exec -T conjur-leader evoke configure master \
    --hostname=conjur-leader-1.mycompany.local \
    --master-altnames="conjur-leader.mycompany.local,conjur-leader-1.mycompany.local" \
    --accept-eula \
    --admin-password="${CONJUR_ADMIN_PASSWORD}" \
    conjur

  echo "Enterprise appliance is ready."

  # Retrieve the admin API key via the REST /authn/login endpoint using the admin
  # password. conjurctl role retrieve-key is OSS-only and not present on the
  # enterprise appliance image.
  CONJUR_CERT_AUTHN_API_KEY="$(docker compose --profile cert exec -T conjur-leader \
    curl -sk --user "admin:${CONJUR_ADMIN_PASSWORD}" \
    https://localhost/authn/conjur/login | tr -d '\r\n')"
  export CONJUR_CERT_AUTHN_API_KEY

  # The self-signed TLS cert is written by evoke at this path inside the container.
  CONJUR_CERT_SSL_CERTIFICATE="$(docker compose --profile cert exec -T conjur-leader \
    cat /opt/conjur/etc/ssl/conjur.pem)"
  export CONJUR_CERT_SSL_CERTIFICATE
}

if [[ "${CONJUR_ENTERPRISE_STARTED:-false}" != "true" ]]; then
  start_conjur_appliance
  export CONJUR_CERT_APPLIANCE_URL="https://conjur-leader-1.mycompany.local"
  export CONJUR_ENTERPRISE_STARTED=true
fi
