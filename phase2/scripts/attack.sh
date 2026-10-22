#!/bin/sh
# 2.3 attack: switch attacker to FORGE, poison example.com, leave www alone.
cd "$(dirname "$0")/.."
MODE=forge docker compose up -d attacker
sleep 3
sh scripts/flush.sh
echo -n "example.com     (expect 172.16.1.30 ROGUE) -> "; docker exec client dig +short example.com
echo -n "www.example.com (expect 172.16.1.20)       -> "; docker exec client dig +short www.example.com
echo "--- fetch example.com ---"
docker exec client curl -s http://example.com | grep -iE 'hacked|rogue'
