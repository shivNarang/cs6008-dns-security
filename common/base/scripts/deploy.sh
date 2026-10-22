#!/bin/sh
# Build images and start the Phase 1 hierarchy.
set -e
cd "$(dirname "$0")/.."
docker compose up --build -d
echo "Waiting for BIND to settle..."
sleep 5
docker compose ps
