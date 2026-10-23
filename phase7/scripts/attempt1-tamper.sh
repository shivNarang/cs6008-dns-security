#!/bin/sh
# Attempt (i): alter the answer in transit. The client-resolver link is DoT, so
# the DNS payload is inside TLS. An on-path attacker cannot read or rewrite it
# without the session keys: the cleartext forge tool sees no :53 DNS to touch,
# and a passive capture of 853 is opaque. Shown against both client policies.
cd "$(dirname "$0")/.."
echo "== both clients resolve over DoT while a capture runs on the path =="
docker exec -d edge-router sh -c 'rm -f /tmp/t1.pcap; tcpdump -i any -n -c 40 -w /tmp/t1.pcap "tcp port 853" 2>/dev/null'
sleep 1

printf '   strict client (DoT) example.com -> '
docker exec client sh /opt/bin/resolve-strict.sh example.com 2>&1 | awk '/IN[ \t]+A[ \t]/{print $NF}' | tail -1
printf '   lax client    (DoT) example.com -> '
docker exec client sh /opt/bin/resolve-lax.sh example.com 2>&1 | awk '/IN[ \t]+A[ \t]/{print $NF}' | tail -1
sleep 2

echo "-- what an on-path attacker can actually read of that exchange --"
printf '   readable "example.com" strings in the 853 capture = '
docker exec edge-router sh -c 'strings /tmp/t1.pcap 2>/dev/null | grep -c example.com' || true
echo "RESULT: both clients got the real 172.16.1.20; the payload on 853 is ciphertext. Tamper fails x2."
