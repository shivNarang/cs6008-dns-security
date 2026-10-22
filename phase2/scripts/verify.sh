#!/bin/sh
# 2.2 transparency: with the attacker RELAYING, resolution is unaffected.
cd "$(dirname "$0")/.."
sh scripts/flush.sh
echo -n "example.com (expect 172.16.1.20) -> "; docker exec client dig +short example.com
docker exec client curl -s http://example.com | grep -i welcome
