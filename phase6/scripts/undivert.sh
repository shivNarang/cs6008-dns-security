#!/bin/sh
# Usage: undivert.sh [client-ip]  (default both clients)
for v in ${*:-172.16.1.10 172.16.1.11}; do
    docker exec edge-router ip route del "${v}/32" via 172.16.1.100 2>/dev/null || true
done
echo "diversion OFF"
