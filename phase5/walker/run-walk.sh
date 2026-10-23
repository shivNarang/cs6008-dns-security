#!/bin/sh
# Install the route to the authoritative subnet, prime the gateway ARP entry the
# walker reads from /proc/net/arp, then idle. The actual walk is run on demand
# with: docker exec walker /opt/walker/zonewalk ...
set -e
if [ -n "$STATIC_ROUTES" ]; then
    printf '%s\n' "$STATIC_ROUTES" | tr ';' '\n' | while IFS= read -r r; do
        [ -n "$r" ] && ip route replace $r 2>/dev/null || true
    done
fi
ping -c1 -W1 "${GATEWAY:-172.16.2.3}" >/dev/null 2>&1 || true
ping -c1 -W1 "${SERVER:-172.16.3.30}" >/dev/null 2>&1 || true
exec sleep infinity
