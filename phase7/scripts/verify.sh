#!/bin/sh
# 7.2: encrypted, authenticated resolution + no cleartext on the last mile.
cd "$(dirname "$0")/.."
echo "== DoT (853), cert validated against resolver.cs6008.local =="
docker exec client kdig +tls +tls-hostname=resolver.cs6008.local +tls-ca \
    @resolver.cs6008.local example.com 2>&1 | grep -iE 'TLS session|status|IN[[:space:]]+A|@853'
echo "== DoH (443) =="
docker exec client kdig +https +tls-hostname=resolver.cs6008.local +tls-ca \
    @resolver.cs6008.local example.com 2>&1 | grep -iE 'HTTP session|@443'
echo "== negative: wrong hostname must fail (no bypass) =="
docker exec client kdig +tls +tls-hostname=wrong.name.local +tls-ca \
    @resolver.cs6008.local example.com 2>&1 | grep -iE 'WARNING|ERROR' | head -1
echo "== no cleartext :53 on edge-router during a DoT lookup =="
docker exec -d edge-router sh -c 'tcpdump -i any -n -c 40 -w /tmp/p7.pcap "tcp port 853 or port 53" 2>/dev/null'
sleep 1; docker exec client kdig +tls +tls-hostname=resolver.cs6008.local +tls-ca @resolver.cs6008.local www.example.com >/dev/null 2>&1; sleep 2
echo -n "  cleartext :53 packets = "; docker exec edge-router tcpdump -nr /tmp/p7.pcap 'port 53' 2>/dev/null | wc -l
echo -n "  encrypted :853 packets = "; docker exec edge-router tcpdump -nr /tmp/p7.pcap 'tcp port 853' 2>/dev/null | wc -l
