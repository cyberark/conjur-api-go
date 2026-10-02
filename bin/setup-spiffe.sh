#!/bin/bash -e
# Sets up a SPIRE server and agent for SPIFFE authn-cert integration tests.
#
# This script:
#   1. Starts the SPIRE server (docker-compose spiffe profile)
#   2. Generates a join token and fetches the SPIRE trust bundle
#   3. Writes both to SPIFFE_TMPDIR and starts the SPIRE agent
#   4. Registers the test workload entry (unix:uid:0)
#   5. Configures Conjur (enterprise appliance) with authn-cert in SPIFFE mode
#   6. Exports environment variables consumed by authn_spiffe_test.go:
#        SPIFFE_SERVICE_ID         - Conjur authn-cert service ID
#        SPIFFE_TRUST_BUNDLE       - PEM of the SPIRE CA trust bundle
#        SPIFFE_WORKLOAD_SPIFFE_ID - SPIFFE ID registered for the test workload

cd "$(dirname "${BASH_SOURCE[0]}")"

. ./utils.sh

# When run standalone (not sourced from test.sh), set a default project name.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conjurapigo_spiffe}"

export SPIFFE_TRUST_DOMAIN="conjur.test"
export SPIFFE_SERVICE_ID="acme-spiffe"
export SPIFFE_WORKLOAD_SPIFFE_ID="spiffe://${SPIFFE_TRUST_DOMAIN}/vm-spiffe"
export SPIFFE_AGENT_SPIFFE_ID="spiffe://${SPIFFE_TRUST_DOMAIN}/spire-agent"

export SPIFFE_JWT_SERVICE_ID="acme-spiffe-jwt"

# SPIFFE_TMPDIR is shared with the SPIRE agent container via the bind mount in
# docker-compose.yml (${SPIFFE_TMPDIR:-/tmp/spiffe-tokens}:/run/spire/secrets).
# It must be set before docker compose up so the compose YAML substitution works.
export SPIFFE_TMPDIR
SPIFFE_TMPDIR="$(mktemp -d)"

function start_spire_server() {
    announce "Pulling SPIRE server image..."
    docker compose --profile spiffe pull spire-server
    echo "Done!"

    announce "Starting SPIRE server..."
    docker compose --profile spiffe up --no-deps -d spire-server

    announce "Waiting for SPIRE server to become ready..."
    local timeout=60 elapsed=0
    until docker compose --profile spiffe exec -T spire-server \
            /opt/spire/bin/spire-server bundle show \
                -socketPath /run/spire/server/private/api.sock \
                -format pem > /dev/null 2>&1; do
        if (( elapsed >= timeout )); then
            echo "ERROR: Timed out waiting for SPIRE server to become ready"
            echo "--- SPIRE server logs ---"
            docker compose --profile spiffe logs spire-server || true
            exit 1
        fi
        sleep 2
        (( elapsed += 2 ))
    done
    echo "SPIRE server is ready."
}

function start_spire_agent() {
    announce "Generating SPIRE join token..."
    local token_output
    token_output="$(docker compose --profile spiffe exec -T spire-server \
        /opt/spire/bin/spire-server token generate \
            -socketPath /run/spire/server/private/api.sock \
            -spiffeID "$SPIFFE_AGENT_SPIFFE_ID" \
            -ttl 3600)"
    # Output format: "Token: <token>"
    JOIN_TOKEN="$(echo "$token_output" | awk '{print $2}')"

    announce "Fetching SPIRE trust bundle..."
    docker compose --profile spiffe exec -T spire-server \
        /opt/spire/bin/spire-server bundle show \
            -socketPath /run/spire/server/private/api.sock \
            -format pem > "$SPIFFE_TMPDIR/bundle.crt"

    announce "Pulling SPIRE agent image..."
    docker compose --profile spiffe pull spire-agent
    echo "Done!"

    announce "Starting SPIRE agent..."
    # Export the join token so Compose substitutes it into the agent entrypoint.
    # The agent image is distroless so the token is passed as a CLI flag, not via start.sh.
    export SPIRE_JOIN_TOKEN="$JOIN_TOKEN"
    docker compose --profile spiffe up --no-deps -d spire-agent

    announce "Waiting for SPIRE agent Workload API socket..."
    local timeout=60 elapsed=0
    # The agent image is distroless (no shell/test). Check the socket via a
    # throwaway busybox container that mounts the same named volume.
    until docker run --rm \
            -v "${COMPOSE_PROJECT_NAME}_spire-agent-socket:/run/spire/sockets" \
            busybox test -S /run/spire/sockets/agent.sock 2>/dev/null; do
        if (( elapsed >= timeout )); then
            echo "ERROR: Timed out waiting for SPIRE agent socket"
            echo "--- SPIRE server logs ---"
            docker compose --profile spiffe logs spire-server || true
            echo "--- SPIRE agent logs ---"
            docker compose --profile spiffe logs spire-agent || true
            exit 1
        fi
        sleep 2
        (( elapsed += 2 ))
    done
    echo "SPIRE agent is ready."
}

function register_workload() {
    local uid
    uid="$(id -u)"
    announce "Registering SPIFFE workload entry (unix:uid:${uid})..."
    docker compose --profile spiffe exec -T spire-server \
        /opt/spire/bin/spire-server entry create \
            -socketPath /run/spire/server/private/api.sock \
            -parentID "$SPIFFE_AGENT_SPIFFE_ID" \
            -spiffeID "$SPIFFE_WORKLOAD_SPIFFE_ID" \
            -selector "unix:uid:${uid}"
    echo "Workload entry registered."
}

function configure_conjur_spiffe() {
    # Requires the enterprise appliance (conjur-leader) to already be running and
    # CONJUR_CERT_APPLIANCE_URL / CONJUR_CERT_AUTHN_API_KEY to be set (by setup-cert-auth.sh).
    if [[ -z "${CONJUR_CERT_APPLIANCE_URL:-}" || -z "${CONJUR_CERT_AUTHN_API_KEY:-}" ]]; then
        echo "ERROR: CONJUR_CERT_APPLIANCE_URL and CONJUR_CERT_AUTHN_API_KEY must be set."
        echo "       Run setup-cert-auth.sh first, or set TEST_CERT=true."
        exit 1
    fi

    announce "Configuring Conjur with authn-cert in SPIFFE mode..."

    export SPIFFE_TRUST_BUNDLE
    SPIFFE_TRUST_BUNDLE="$(cat "$SPIFFE_TMPDIR/bundle.crt")"

    # Load the SPIRE trust bundle as the authn-cert CA cert in Conjur.
    # The authn_spiffe_test.go creates its own policies and calls AddSecret to load
    # the CA cert, so no inline Conjur policy setup is done here.
    echo "Trust bundle ready for test (exported as SPIFFE_TRUST_BUNDLE)."
}

function start_spire_oidc() {
    announce "Pulling SPIRE OIDC discovery provider..."
    docker compose --profile spiffe pull spire-oidc
    echo "Done!"

    announce "Starting SPIRE OIDC discovery provider..."
    docker compose --profile spiffe up --no-deps -d spire-oidc

    # The OIDC provider is ready once its /keys endpoint returns a response.
    announce "Waiting for SPIRE OIDC discovery provider to become ready..."
    local timeout=60 elapsed=0
    until docker run --rm \
            --network "${COMPOSE_PROJECT_NAME}_spiffe" \
            curlimages/curl:latest \
            curl -sf "http://spire-oidc:8085/keys" > /dev/null 2>&1; do
        if (( elapsed >= timeout )); then
            echo "ERROR: Timed out waiting for SPIRE OIDC discovery provider"
            docker compose --profile spiffe logs spire-oidc || true
            exit 1
        fi
        sleep 2
        (( elapsed += 2 ))
    done
    echo "SPIRE OIDC discovery provider is ready."

    # SPIFFE_JWT_ISSUER_URL is the OIDC issuer URL.  The spire-oidc container is
    # reachable from other containers on the 'spiffe' network by its hostname;
    # the Conjur appliance (also on that network) will use this to fetch the JWKS.
    export SPIFFE_JWT_ISSUER_URL="http://spire-oidc:8085"
    echo "  OIDC issuer URL : $SPIFFE_JWT_ISSUER_URL"
}

start_spire_server
start_spire_agent
register_workload
# configure_conjur_spiffe requires the enterprise appliance and authn-cert setup.
# Skip it when TEST_CERT is not true (JWT-only SPIFFE tests don't need it).
if [[ "${TEST_CERT:-false}" == "true" ]]; then
    configure_conjur_spiffe
fi
start_spire_oidc

announce "SPIFFE test environment ready."
echo "  Trust domain    : $SPIFFE_TRUST_DOMAIN"
echo "  X.509 service   : $SPIFFE_SERVICE_ID"
echo "  JWT service     : $SPIFFE_JWT_SERVICE_ID"
echo "  Workload ID     : $SPIFFE_WORKLOAD_SPIFFE_ID"
echo "  Token dir       : $SPIFFE_TMPDIR"
echo "  Socket volume   : ${COMPOSE_PROJECT_NAME}_spire-agent-socket"
echo "  OIDC issuer URL : ${SPIFFE_JWT_ISSUER_URL:-<not started>}"
