#!/bin/sh
# Run sign-all.sh inside the base lab image (has BIND's dnssec-* tools),
# unsigned zones mounted read-only, signed output written to ./out.
# Usage:  sh run.sh          # NSEC (walkable)
#         NSEC3=1 sh run.sh  # NSEC3 (Phase 5 fixed)
set -e
cd "$(dirname "$0")"
IMG=cs6008-dns-base
# build the shared base image once (stable tag) if missing
docker image inspect "$IMG" >/dev/null 2>&1 || \
    docker build -t "$IMG" ../base
ZONES="$(cd ../base/zones && pwd)"
mkdir -p out
docker run --rm \
    -e NSEC3="${NSEC3:-0}" \
    -v "$ZONES":/work/zones:ro \
    -v "$(pwd)":/work/signing \
    -v "$(pwd)/out":/work/out \
    --entrypoint sh "$IMG" /work/signing/sign-all.sh
echo
echo "Signed zones + trust anchor are in: $(pwd)/out"
