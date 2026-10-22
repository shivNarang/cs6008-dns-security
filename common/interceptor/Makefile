# Build the libpcap interceptor. Needs libpcap headers (libpcap-dev).
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lpcap

dns_intercept: dns_intercept.c
	$(CC) $(CFLAGS) -o $@ dns_intercept.c $(LDLIBS)

clean:
	rm -f dns_intercept
.PHONY: clean
