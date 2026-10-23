#!/bin/sh
# Phase 4, Run A: com DOES publish a DS for example.com (secure delegation).
# The attacker strips the signature and forges the A. Expected: the resolver
# still demands a signature, cannot get one, and returns SERVFAIL. Attack fails.
set -e
cd "$(dirname "$0")/.."

echo "== sign (Run A: DS present) =="
NODS="" sh sign.sh

echo "== (re)deploy on a clean cache =="
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
docker compose down -t 2 >/dev/null 2>&1 || true
MODE=strip docker compose up -d
echo "waiting for BIND..."; sleep 8
docker exec client dig +time=5 +tries=2 example.com >/dev/null 2>&1 || true   # prime root/com

echo
echo "== 4.2 baseline: no diversion, example.com validates (expect AD flag + 172.16.1.20) =="
sh scripts/undivert.sh
sh scripts/flush.sh
docker exec client dig +dnssec example.com | grep -E "flags:|status:|IN[[:space:]]+A" | head -3

echo
echo "== 4.3 Run A attack: divert through the attacker (STRIP) and retry =="
sh scripts/divert.sh
sh scripts/flush.sh
echo "-- client resolve example.com (expect SERVFAIL) --"
docker exec client dig +time=8 +tries=1 example.com | grep -E "status:" | head -1
echo "-- resolver log (expect 'no valid signature' / validation failure) --"
docker logs resolver 2>&1 | grep -iE "no valid signature|RRSIG|broken trust|SERVFAIL|insecurity proof" | tail -3
sh scripts/undivert.sh
echo
echo "Run A done: stripping the signature does NOT downgrade a zone whose parent authenticates the delegation."
