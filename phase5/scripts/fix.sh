#!/bin/sh
# 5.3 fix: re-sign the zone with NSEC3 and re-run the exact same walk. The chain
# of plaintext names is gone, so the walk recovers nothing, while a nonexistent
# name still gets an authenticated denial (now via NSEC3).
set -e
cd "$(dirname "$0")/.."
echo "== re-sign with NSEC3 and reload the authoritative servers =="
NSEC3=1 sh sign.sh
docker compose up -d --force-recreate root-ns tld-ns domain-ns >/dev/null
sleep 5

echo
echo "== re-run the same walk (expect: none recovered) =="
docker exec walker sh /opt/zonewalk.sh 172.16.3.30 example.com

echo
echo "== denial of existence still works and is still authenticated (NSEC3) =="
docker exec walker dig +dnssec +norec +noall +authority @172.16.3.30 nope.example.com A \
    | grep -E "NSEC3" | head -2
