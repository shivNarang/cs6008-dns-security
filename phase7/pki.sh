#!/bin/sh
set -e
cd "$(dirname "$0")"
IMG=cs6008-dns-base
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" ../common/base
mkdir -p pki/out
docker run --rm -v "$(pwd)/pki":/work --entrypoint sh "$IMG" /work/gen-ca.sh
