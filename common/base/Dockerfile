# All-purpose lab node: BIND 9.20 + dig/delv + routing + capture tools.
# Built with host internet; runs fully offline on internal Docker networks.
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bind9 bind9-dnsutils bind9-utils \
        iproute2 iptables iputils-ping curl wget tcpdump ldnsutils \
        knot-dnsutils openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
