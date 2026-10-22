#!/bin/sh
# Generic node bootstrap: enable forwarding (routers), install static routes,
# optionally pin the stub resolver, then exec the real command.
set -e

if [ "$IP_FORWARD" = "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
fi

if [ -n "$STATIC_ROUTES" ]; then
    printf '%s\n' "$STATIC_ROUTES" | tr ';' '\n' | while IFS= read -r route; do
        [ -z "$route" ] && continue
        # shellcheck disable=SC2086
        ip route replace $route || echo "warn: could not add route: $route" >&2
    done
fi

if [ -n "$RESOLV_NS" ]; then
    echo "nameserver $RESOLV_NS" > /etc/resolv.conf 2>/dev/null || true
fi

exec "$@"
