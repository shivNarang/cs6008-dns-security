#!/bin/sh
# Phase 1 verification: resolution, web fetch, and isolation check.
cd "$(dirname "$0")/.."

echo "== [1] client resolves example.com (expect 172.16.1.20) =="
docker exec client dig +short example.com

echo "== [2] client resolves www.example.com (expect 172.16.1.20) =="
docker exec client dig +short www.example.com

echo "== [3] client fetches http://example.com (expect real page) =="
docker exec client curl -s http://example.com | grep -i -E 'welcome|legitimate'

echo "== [4] isolation: direct query to root-ns 172.16.3.10 should FAIL/timeout =="
docker exec client dig +time=2 +tries=1 @172.16.3.10 example.com | grep -E 'status:|timed out|no servers' || echo "(no answer - isolation holds)"

echo "== [5] resolver's route to the authoritative subnet =="
docker exec resolver ip route get 172.16.3.10
