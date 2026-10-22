#!/bin/sh
set -e
cd "$(dirname "$0")/.."
sh sign.sh                       # (re)generate signed zones + trust anchor
docker compose up -d
echo "Waiting for BIND..."; sleep 6
docker compose ps
