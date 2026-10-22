#!/bin/sh
# Phase 3 verification: signed, validated resolution (no attacker in path).
cd "$(dirname "$0")/.."
echo "== [1] dig +dnssec example.com — expect 'ad' flag + RRSIG =="
docker exec client dig +dnssec example.com | grep -E "flags:|status:|IN[[:space:]]+A|RRSIG" | head -6
echo
echo "== [2] delv full-chain validation with the root KSK =="
docker cp configs/resolver/trust-anchor.conf client:/tmp/ta.conf >/dev/null 2>&1
docker exec client delv -a /tmp/ta.conf @172.16.2.10 example.com 2>&1 | head -3
echo
echo "== [3] web fetch still works =="
docker exec client curl -s http://example.com | grep -i welcome
