#!/bin/sh
# Sign the Phase 5 hierarchy. The example.com zone here carries the hidden names.
#   sh sign.sh           # NSEC  (walkable "before" zone)
#   NSEC3=1 sh sign.sh   # NSEC3 (the fix)
set -e
cd "$(dirname "$0")"
IMG=cs6008-dns-base
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" ../common/base
mkdir -p signed
docker run --rm -e NSEC3="${NSEC3:-0}" \
    -v "$(pwd)/zones":/work/zones:ro \
    -v "$(cd ../common/signing && pwd)":/work/signing \
    -v "$(pwd)/signed":/work/out \
    --entrypoint sh "$IMG" /work/signing/sign-all.sh
cp signed/trust-anchor.conf configs/resolver/trust-anchor.conf 2>/dev/null || true
echo "Signed (NSEC3=${NSEC3:-0}). Zones in ./signed."
