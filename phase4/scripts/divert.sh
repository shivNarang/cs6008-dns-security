#!/bin/sh
# Divert the resolver's inbound traffic through the attacker (route on core-router only).
docker exec core-router ip route replace 172.16.2.10/32 via 172.16.2.100
echo "diversion ON: core-router 172.16.2.10 -> via 172.16.2.100 (attacker)"
docker exec core-router ip route get 172.16.2.10
