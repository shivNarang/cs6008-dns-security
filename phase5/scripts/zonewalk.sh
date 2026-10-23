#!/bin/sh
# NSEC zone walker. Starting from the zone apex alone, follow the NSEC chain:
# each existing name's NSEC record points at the next existing name, in canonical
# order, so one query per name recovers the whole zone. No AXFR, no wordlist, and
# no Scapy/dnspython: just `dig`, since this is enumeration by ordinary queries,
# not packet forgery.
#
# Usage: zonewalk.sh [auth-server-ip] [zone]
set -e
NS="${1:-172.16.3.30}"
ZONE="${2:-example.com}"

current="$ZONE."
start="$ZONE."
queries=0
recovered=""

echo "walking $ZONE via NSEC at $NS"
while [ "$queries" -lt 50 ]; do
    out=$(dig +dnssec +norec +noall +answer @"$NS" "$current" NSEC 2>/dev/null)
    queries=$((queries + 1))
    # the NSEC record's 5th field is the next owner name in the chain
    next=$(printf '%s\n' "$out" | awk '$4=="NSEC"{print $5; exit}')
    if [ -z "$next" ]; then
        echo "  no NSEC returned for $current : chain not exposed (NSEC3 or not signed)"
        break
    fi
    # record every owner except the apex itself
    if [ "$current" != "$start" ]; then
        recovered="$recovered $current"
    fi
    [ "$next" = "$start" ] && break     # wrapped back to the apex: done
    current="$next"
done

echo
echo "queries sent : $queries"
echo "names recovered:"
if [ -z "$recovered" ]; then
    echo "  (none)"
else
    for n in $recovered; do
        a=$(dig +short +norec @"$NS" "$n" A 2>/dev/null | head -1)
        printf '  %-24s %s\n' "$n" "${a:-<no A>}"
    done
fi
