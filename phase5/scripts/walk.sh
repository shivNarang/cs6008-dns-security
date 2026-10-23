#!/bin/sh
# 5.3: run the NSEC walk from the attacker node (the `walker` container).
cd "$(dirname "$0")/.."
docker exec walker sh /opt/zonewalk.sh 172.16.3.30 example.com
