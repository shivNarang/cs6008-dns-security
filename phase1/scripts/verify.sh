#!/bin/sh
cd "$(dirname "$0")/.."
echo "== [1] example.com (expect 172.16.1.20) =="; docker exec client dig +short example.com
echo "== [2] www.example.com (expect 172.16.1.20) =="; docker exec client dig +short www.example.com
echo "== [3] real page =="; docker exec client curl -s http://example.com | grep -i welcome
echo "== [4] isolation: direct to root-ns should fail =="
docker exec client dig +time=2 +tries=1 @172.16.3.10 example.com 2>&1 | grep -iE 'no servers|timed out' || echo "(no answer)"
echo "== [5] resolver route to auth subnet =="; docker exec resolver ip route get 172.16.3.10
