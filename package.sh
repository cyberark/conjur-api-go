#!/bin/bash -e

echo "==> Packaging..."

rm -rf output/dist && mkdir -p output/dist

tar --exclude='./.git' --exclude='./output' -cvzf ./output/dist/conjur-api-go.tar.gz .

# # Make the checksums
echo "==> Checksumming..."
cd output/dist

if which sha256sum; then
    sha256sum * > SHA256SUMS.txt
elif which shasum; then
    shasum -a256 * > SHA256SUMS.txt
else
  echo "couldn't find sha256sum or shasum"
  exit 1
fi
