#!/bin/bash -e

echo "==> Packaging..."

rm -rf output/dist && mkdir -p output/dist

tar --exclude='./.git' --exclude='./output' -cvzf ./output/dist/conjur-api-go.tar.gz .

# # Make the checksums
echo "==> Checksumming..."
cd output/dist
shasum -a256 * > SHA256SUMS.txt
