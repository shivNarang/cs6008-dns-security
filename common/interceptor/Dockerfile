# Attacker node: builds the libpcap interceptor from source.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential libpcap-dev libpcap0.8 \
        iproute2 iputils-ping dnsutils tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/intercept
COPY dns_intercept.c Makefile ./
RUN make
COPY run-attack.sh /usr/local/bin/run-attack.sh
RUN chmod +x /usr/local/bin/run-attack.sh
ENTRYPOINT ["/usr/local/bin/run-attack.sh"]
