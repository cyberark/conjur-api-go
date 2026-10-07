#!/bin/bash -e
# Sets up the enterprise Conjur appliance and generates client certificates
# for authn-cert (authn-x509) integration tests.
#
# This script:
#   1. Pulls and starts the conjur-appliance enterprise container
#   2. Configures it as a Conjur master (which issues a self-signed TLS certificate)
#   3. Generates a CA key+cert and a single client cert/key pair signed by that CA.
#      The client cert includes:
#      - CN=vm-01 for request mode tests
#      - URI SAN=spiffe://conjur.test/vm-spiffe for SPIFFE mode tests
#   4. Exports the following environment variables consumed by authn_cert_test.go:
#        CONJUR_CERT_APPLIANCE_URL   - HTTPS URL of the enterprise appliance
#        CONJUR_CERT_AUTHN_API_KEY   - admin API key for that appliance
#        CONJUR_CERT_SSL_CERTIFICATE - PEM of the appliance's self-signed TLS cert
#        CONJUR_AUTHN_CERT_FILE      - path to client cert inside test container (/certs/...)
#        CONJUR_AUTHN_CERT_KEY_FILE  - path to client key  inside test container (/certs/...)
#        TEST_CERT_CA_CERT           - PEM content of the issuing CA cert
#        CERT_TMPDIR                 - host-side tmpdir mounted at /certs in the test container

cd "$(dirname "${BASH_SOURCE[0]}")"

. ./utils.sh

# When run standalone (not sourced from test.sh), set a default project name.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conjurapigo_cert}"

function generate_cert_auth_pki() {
  announce "Generating CA and client certificates for authn-cert tests..."

  export CERT_TMPDIR
  CERT_TMPDIR="$(mktemp -d)"

  # CA: 4096-bit RSA key + self-signed certificate (10-year validity for CI stability)
  openssl genrsa -out "$CERT_TMPDIR/ca.key" 4096 2>/dev/null
  openssl req -new -x509 -days 3650 \
    -key "$CERT_TMPDIR/ca.key" \
    -out "$CERT_TMPDIR/ca.pem" \
    -subj "/C=US/O=ConjurTestCA/CN=Conjur Test Certificate Authority"

  # Client key + CSR. CN matches the authn-cert/cn annotation for request mode.
  # (see authCertRolesPolicy in authn_cert_test.go: "authn-cert/cn: vm-01").
  openssl genrsa -out "$CERT_TMPDIR/client.key" 2048 2>/dev/null
  openssl req -new \
    -key "$CERT_TMPDIR/client.key" \
    -out "$CERT_TMPDIR/client.csr" \
    -subj "/C=US/O=ConjurTest/CN=vm-01"

  # Add SPIFFE URI SAN to the same cert so it can be reused for SPIFFE mode.
  cat > "$CERT_TMPDIR/client.ext" <<EOF
subjectAltName=URI:spiffe://conjur.test/vm-spiffe
extendedKeyUsage=clientAuth
EOF

  # Sign the client cert with the CA.
  openssl x509 -req -days 365 \
    -in "$CERT_TMPDIR/client.csr" \
    -CA "$CERT_TMPDIR/ca.pem" \
    -CAkey "$CERT_TMPDIR/ca.key" \
    -CAcreateserial \
    -extfile "$CERT_TMPDIR/client.ext" \
    -out "$CERT_TMPDIR/client.pem" 2>/dev/null

  # Paths as seen inside the test container (CERT_TMPDIR is mounted at /certs)
  export CONJUR_AUTHN_CERT_FILE="/certs/client.pem"
  export CONJUR_AUTHN_CERT_KEY_FILE="/certs/client.key"

  export TEST_CERT_CA_CERT
  TEST_CERT_CA_CERT="$(cat "$CERT_TMPDIR/ca.pem")"
}

# start-conjur-enterprise.sh is a no-op if test.sh already started the appliance
# for TEST_ENTERPRISE=true.
source ./start-conjur-enterprise.sh
generate_cert_auth_pki

announce "Certificate auth test environment ready."
echo "  Appliance URL : $CONJUR_CERT_APPLIANCE_URL"
echo "  Cert dir      : $CERT_TMPDIR"
