#!/bin/sh
set -e
cd "$(dirname "$0")/.."
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
docker compose up -d
echo "Waiting for BIND..."; sleep 5
docker compose ps
