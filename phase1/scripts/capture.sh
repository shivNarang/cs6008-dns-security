#!/bin/sh
# Capture one full recursive resolution on core-router -> resolution.pcap
cd "$(dirname "$0")/.."
docker exec resolver rndc flush 2>/dev/null || true
docker exec -d core-router sh -c 'tcpdump -i any -w /tmp/resolution.pcap udp port 53 or tcp port 53'
sleep 1
docker exec client dig +tries=1 newname.example.com >/dev/null 2>&1
docker exec client dig example.com >/dev/null 2>&1
sleep 1
docker exec core-router pkill tcpdump 2>/dev/null || true
sleep 1
docker cp core-router:/tmp/resolution.pcap ./resolution.pcap
echo "Saved $(pwd)/resolution.pcap"
echo "Inspect with:  tshark -r resolution.pcap -Y dns"
