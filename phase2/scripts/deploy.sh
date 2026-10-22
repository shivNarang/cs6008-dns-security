#!/bin/sh
set -e
cd "$(dirname "$0")/.."
# base image must exist (built from common/base); build attacker from source
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
MODE="${MODE:-relay}" docker compose up --build -d
echo "Waiting..."; sleep 5
sh scripts/divert.sh
docker compose ps
