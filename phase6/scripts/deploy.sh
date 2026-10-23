#!/bin/sh
set -e
cd "$(dirname "$0")/.."
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
sh sign.sh                       # signed zones + trust anchor (same as Phase 3)
MODE=relay docker compose up --build -d
echo "waiting for BIND..."; sleep 6
docker compose ps
