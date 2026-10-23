#!/bin/sh
# 6.2: with the attacker relaying (not forging), the client resolves normally.
cd "$(dirname "$0")/.."
VICTIM=172.16.1.10 MODE=relay docker compose up -d attacker >/dev/null 2>&1
sleep 2
sh scripts/divert.sh 172.16.1.10 >/dev/null
sh scripts/flush.sh >/dev/null
printf "client-a example.com (expect 172.16.1.20) -> "; docker exec client-a dig +short example.com
docker exec client-a curl -s http://example.com | grep -i welcome
sh scripts/undivert.sh >/dev/null
