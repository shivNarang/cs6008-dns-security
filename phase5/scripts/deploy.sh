#!/bin/sh
# Deploy the Phase 5 signed hierarchy. NSEC by default (the walkable zone).
set -e
cd "$(dirname "$0")/.."
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
NSEC3="${NSEC3:-0}" sh sign.sh
docker compose up --build -d
echo "waiting for BIND..."; sleep 6
docker compose ps
