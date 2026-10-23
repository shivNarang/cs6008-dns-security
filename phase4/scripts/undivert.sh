#!/bin/sh
docker exec core-router ip route del 172.16.2.10/32 via 172.16.2.100 2>/dev/null || true
echo "diversion OFF"
