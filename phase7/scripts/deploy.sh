#!/bin/sh
set -e
cd "$(dirname "$0")/.."
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
sh pki.sh          # private CA + resolver cert (SAN resolver.cs6008.local)
sh sign.sh         # signed zones + trust anchor
docker compose up -d
echo "Waiting..."; sleep 6
docker compose ps
