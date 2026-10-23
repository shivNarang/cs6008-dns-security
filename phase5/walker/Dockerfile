# Zone-walker node: builds the libpcap NSEC walker from source.
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential libpcap-dev libpcap0.8 \
        iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/walker
COPY zonewalk.c Makefile ./
RUN make
COPY run-walk.sh /usr/local/bin/run-walk.sh
RUN chmod +x /usr/local/bin/run-walk.sh
ENTRYPOINT ["/usr/local/bin/run-walk.sh"]
