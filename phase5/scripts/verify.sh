#!/bin/sh
# 5.2: ask for a name that does not exist and show how a signed zone answers.
# With NSEC, the authenticated denial names the two existing neighbours that the
# missing name falls between, which is exactly the leak the walk exploits.
# dig is used here only as an inspection tool (the brief allows that); the walk
# itself is the C libpcap walker in walker/zonewalk.c.
cd "$(dirname "$0")/.."
echo "== query a nonexistent name (nope.example.com) at domain-ns =="
docker exec resolver dig +dnssec +norec +noall +authority @172.16.3.30 nope.example.com A \
    | grep -E "NSEC|NSEC3" | head -4
echo
echo "The NSEC in the authority section proves nonexistence by pointing from one"
echo "real name to the next, so it reveals a real neighbour of the queried name."
