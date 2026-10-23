#!/bin/sh
# Divert a client's inbound replies through the attacker (route on edge-router only,
# no ARP spoofing). Usage: divert.sh [client-ip]  (default 172.16.1.10 = client-a)
VICTIM="${1:-172.16.1.10}"
docker exec edge-router ip route replace "${VICTIM}/32" via 172.16.1.100
echo "diversion ON: edge-router ${VICTIM} -> via 172.16.1.100 (attacker)"
docker exec edge-router ip route get "$VICTIM"
