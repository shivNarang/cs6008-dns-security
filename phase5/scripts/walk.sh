#!/bin/sh
# 5.3: run the NSEC walk from the attacker node (C libpcap walker, not dig).
cd "$(dirname "$0")/.."
docker exec walker sh -c 'ping -c1 -W1 172.16.2.3 >/dev/null 2>&1; ping -c1 -W1 172.16.3.30 >/dev/null 2>&1; \
  /opt/walker/zonewalk -i eth0 -s 172.16.3.30 -g 172.16.2.3 -S 172.16.2.100 -z example.com'
