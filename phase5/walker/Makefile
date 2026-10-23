# Build the libpcap zone-walker. Needs libpcap headers (libpcap-dev).
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lpcap

zonewalk: zonewalk.c
	$(CC) $(CFLAGS) -o $@ zonewalk.c $(LDLIBS)

clean:
	rm -f zonewalk
.PHONY: clean
