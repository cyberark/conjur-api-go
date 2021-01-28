#!/bin/bash -e

cd "$(dirname "$0")"

echo "==> Packaging..."
build_dir="../output/dist"
rm -rf "$build_dir"
mkdir -p "$build_dir"

tar --exclude='../.git' --exclude='../output' -cvzf "$build_dir/conjur-api-go.tar.gz" .

# # Make the checksums
echo "==> Checksumming..."
pushd "$build_dir"
  if which sha256sum; then
      sha256sum * > SHA256SUMS.txt
  elif which shasum; then
      shasum -a256 * > SHA256SUMS.txt
  else
    echo "couldn't find sha256sum or shasum"
    exit 1
  fi
popd
