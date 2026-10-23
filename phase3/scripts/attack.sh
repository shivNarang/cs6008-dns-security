#!/bin/sh
# 3.3 attack: re-run the Phase 2 forgery against the validating resolver.
# The forged (unsigned) answer is rejected with SERVFAIL.
set -e
cd "$(dirname "$0")/.."
sh scripts/divert.sh
sh scripts/flush.sh
echo "== Querying example.com under forgery (expect SERVFAIL) =="
docker exec client dig example.com | grep -E "status:|ANSWER:" || true
echo
echo "== Resolver log (expect validation failure) =="
docker logs resolver 2>&1 | grep -iE 'RRSIG failed|validating' | tail -2 || true
