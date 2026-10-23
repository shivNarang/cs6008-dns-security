#!/bin/sh
# 6.3 Client B (locally validating): same forgery, but client-b validates the
# answer itself against its own root trust anchor with delv. The forged A has no
# matching signature, so delv rejects it. A plain `dig` on the same box would be
# fooled, which shows the difference is the local validation, not the network.
set -e
cd "$(dirname "$0")/.."
echo "== point the attacker at client-b and forge =="
VICTIM=172.16.1.11 MODE=forge docker compose up -d attacker >/dev/null 2>&1
sleep 2
sh scripts/divert.sh 172.16.1.11 >/dev/null
sh scripts/flush.sh >/dev/null

echo "-- plain dig on client-b (no local validation) would accept the forgery --"
docker exec client-b dig +short +time=5 +tries=1 example.com

echo "-- delv on client-b, validating against its own root anchor --"
docker exec client-b delv -a /etc/bind/trust-anchor.conf @172.16.2.10 example.com 2>&1 | head -4
sh scripts/undivert.sh 172.16.1.11 >/dev/null
