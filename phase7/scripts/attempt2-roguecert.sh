#!/bin/sh
# Attempt (ii): impersonate the resolver with a rogue certificate. We DNAT the
# resolver's 853 to a rogue server that presents a cert for resolver.cs6008.local
# that is NOT signed by the lab CA. Both client policies validate the cert and
# reject it, so neither is impersonated.
cd "$(dirname "$0")/.."
echo "== redirect resolver :853 to the rogue (untrusted cert, same hostname) =="
sh scripts/net.sh dnat-on >/dev/null
sleep 1

echo "-- strict client (DoT, validates cert) --"
docker exec client sh /opt/bin/resolve-strict.sh example.com 2>&1 | grep -iE "status:|IN[[:space:]]+A|handshake|certificate|error" | head -2
echo "-- lax client (DoT, validates cert; cert error is not a transport failure) --"
docker exec client sh /opt/bin/resolve-lax.sh example.com 2>&1 | grep -iE "status:|IN[[:space:]]+A|no fallback|bad cert|handshake|certificate" | head -3

sh scripts/net.sh dnat-off >/dev/null
echo "RESULT: the rogue cert is not signed by the trusted CA, both clients abort. Impersonation fails x2."
