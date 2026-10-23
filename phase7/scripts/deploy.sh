#!/bin/sh
set -e
cd "$(dirname "$0")/.."
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
sh pki.sh          # private CA + resolver cert + rogue cert
sh sign.sh         # signed zones + trust anchor
MODE=relay docker compose up --build -d
echo "Waiting..."; sleep 7
docker compose ps
