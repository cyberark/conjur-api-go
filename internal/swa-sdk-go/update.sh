#!/usr/bin/env bash
#
# Copies swa-sdk-go from a local checkout into this directory, trimmed to just
# what conjur-api-go needs, with import paths rewritten to the internal path.
#
# This internal copy is temporary (see docs/adr/0001-swa-sdk-integration.md):
# it exists only until the public swa-sdk-go module ships. Re-run this script
# against a newer checkout to re-sync.
#
# Usage: ./update.sh <path-to-swa-sdk-go-checkout> [commit-sha]
#
# The commit SHA is recorded in VERSION so a bug can be triaged as
# conjur-api-go's wrapper vs. an upstream swa-sdk-go issue without guessing
# which revision is actually vendored. It's taken from the second argument if
# given, otherwise auto-detected via `git -C <checkout> rev-parse HEAD` — one
# of the two is required, since an unversioned frozen copy defeats the point.

set -euo pipefail

SRC="${1:-}"
COMMIT="${2:-}"
if [ -z "$SRC" ]; then
  echo "usage: $0 <path-to-swa-sdk-go-checkout> [commit-sha]" >&2
  exit 1
fi
if [ ! -f "$SRC/go.mod" ]; then
  echo "error: $SRC does not look like a Go module checkout (missing go.mod)" >&2
  exit 1
fi
# Module path is read from the checkout's own go.mod rather than hardcoded
# here, so this script doesn't need to name swa-sdk-go's (internal) source
# host/org — only that it's a "swa-sdk-go" module.
OLD_IMPORT="$(awk '$1 == "module" { print $2; exit }' "$SRC/go.mod")"
case "$OLD_IMPORT" in
  */swa-sdk-go) ;;
  *)
    echo "error: $SRC's go.mod module path ($OLD_IMPORT) doesn't look like a swa-sdk-go checkout" >&2
    exit 1
    ;;
esac
if [ -z "$COMMIT" ]; then
  COMMIT="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)"
fi
if [ -z "$COMMIT" ]; then
  echo "error: could not determine the source commit SHA (checkout isn't a git repo and no commit-sha argument was given)" >&2
  echo "       pass it explicitly: $0 $SRC <commit-sha>" >&2
  exit 1
fi

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$(basename "${BASH_SOURCE[0]}")"

NEW_IMPORT="github.com/cyberark/conjur-api-go/internal/swa-sdk-go"

# Directories/files to keep from the source checkout, relative to $SRC.
KEEP=(
  # root "swa" package: client, transport, options, retry, pagination, apply,
  # per-resource services, validation, and their own unit tests.
  "apply.go" "apply_test.go"
  "auth.go"
  "client.go" "client_test.go"
  "doc.go"
  "errors.go"
  "interfaces.go"
  "node_groups.go"
  "options.go"
  "ops.go"
  "pagination.go"
  "retry.go"
  "server_groups.go"
  "servers.go"
  "transport.go" "transport_test.go"
  "trust_domains.go"
  "types.go"
  "validation.go" "validation_test.go"
  "wellknown.go"
  # newMockAPI helper (httptest-based, no mockery dependency) shared by
  # client_test.go, apply_test.go, validation_test.go
  "mockserver_test.go"
  # public error surface
  "swaerrors"
  # generated low-level client (models + client only; regen tooling dropped)
  "internal/gen/swa/swa.gen.go"
  # fake HTTP server for tests (real generated routing, not hand-stubbed).
  # Vendored as its own Go module (see the go.mod backup/restore below) to
  # keep its echo/oapi-codegen dependencies out of the root module.
  "swafake"
)

# Explicitly NOT kept (left here so the exclusion is documented, not silent):
#   auth/          - wraps conjur-api-go itself; would be a circular import
#   mocks/         - mockery-generated interface mocks, unused by conjur-api-go
#   swatest/       - depends on mocks/
#   .mockery.yaml, Makefile, generate.go, README.md, example_test.go,
#   internal/gen/swa/cfg.yaml, internal/gen/swa/gen.go
#     - SDK-authoring/regeneration tooling, not needed for a frozen copy

# swafake is vendored as its own Go module (isolating its echo/oapi-codegen
# dependencies from the root module's go.mod). Upstream's swafake isn't a
# separate module, so its go.mod/go.sum are hand-maintained here and must
# survive the wipe-and-recopy below regardless of what $SRC provides.
GOMOD_BACKUP="$(mktemp -d)"
for f in go.mod go.sum; do
  if [ -f "$DEST/swafake/$f" ]; then
    cp "$DEST/swafake/$f" "$GOMOD_BACKUP/$f"
  fi
done

echo "Removing current contents of $DEST (except $SELF)..."
find "$DEST" -mindepth 1 -name "$SELF" -prune -o -mindepth 1 -print0 | xargs -0 rm -rf

echo "Copying trimmed file set from $SRC..."
for rel in "${KEEP[@]}"; do
  src_path="$SRC/$rel"
  dest_path="$DEST/$rel"
  if [ ! -e "$src_path" ]; then
    echo "warning: $src_path not found in source checkout, skipping" >&2
    continue
  fi
  mkdir -p "$(dirname "$dest_path")"
  cp -R "$src_path" "$dest_path"
done

# swafake carries its own tool files and a nested generated server stub;
# drop the tool files, keep the generated server.
rm -f "$DEST/swafake/Makefile" "$DEST/swafake/.mockery.yaml"
rm -f "$DEST/swafake/internal/serverapi/swa/cfg.yaml" "$DEST/swafake/internal/serverapi/swa/gen.go"

echo "Restoring swafake's hand-maintained go.mod/go.sum..."
rm -f "$DEST/swafake/go.mod" "$DEST/swafake/go.sum"
for f in go.mod go.sum; do
  if [ -f "$GOMOD_BACKUP/$f" ]; then
    cp "$GOMOD_BACKUP/$f" "$DEST/swafake/$f"
  fi
done
rm -rf "$GOMOD_BACKUP"

echo "Rewriting import paths ($OLD_IMPORT -> $NEW_IMPORT)..."
grep -rl "$OLD_IMPORT" "$DEST" --include="*.go" | while IFS= read -r f; do
  sed -i.bak "s#${OLD_IMPORT}#${NEW_IMPORT}#g" "$f"
  rm -f "$f.bak"
done

cat > "$DEST/VERSION" <<EOF
source: swa-sdk-go
commit: $COMMIT
synced: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

cat <<EOF

Done. Next steps:
  cd $(cd "$DEST/../.." && pwd)
  go mod tidy
  go build ./internal/... && go vet ./internal/...
  (cd internal/swa-sdk-go/swafake && go mod tidy && go build ./... && go vet ./... && go test ./...)
EOF
