#!/bin/sh
# Lax client policy: prefer DoT, but if the encrypted TRANSPORT is unavailable
# (cannot connect to 853), fall back to plain cleartext :53. A bad certificate is
# an attack, not an unavailable transport, so it does NOT trigger fallback.
NAME=resolver.cs6008.local
PLAIN=172.16.2.10
Q="${1:-example.com}"

out=$(kdig +tls +tls-hostname="$NAME" +tls-ca @"$NAME" "$Q" A 2>&1)
if printf '%s\n' "$out" | grep -q "status: NOERROR"; then
    printf '%s\n' "$out"                       # DoT succeeded
    exit 0
fi
# distinguish "transport down" from "cert rejected"
if printf '%s\n' "$out" | grep -qiE "connect|refused|timed out|unreachable|no route"; then
    echo "[lax] DoT transport unavailable -> falling back to cleartext :53"
    kdig @"$PLAIN" "$Q" A
else
    echo "[lax] DoT failed and it was NOT a transport problem (bad cert?): no fallback"
    printf '%s\n' "$out" | grep -iE "warning|error" | head -2
    exit 1
fi
