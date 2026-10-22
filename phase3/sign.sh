#!/bin/sh
# Produce the signed zones + trust anchor for Phase 3 using the shared signer.
set -e
cd "$(dirname "$0")"
OUT="$(pwd)/signed" NSEC3="${NSEC3:-0}"
export OUT NSEC3
# run the shared signer, writing into ./signed
IMG=cs6008-dns-base
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" ../common/base
mkdir -p signed
docker run --rm -e NSEC3="$NSEC3" \
    -v "$(cd ../common/base/zones && pwd)":/work/zones:ro \
    -v "$(cd ../common/signing && pwd)":/work/signing \
    -v "$(pwd)/signed":/work/out \
    --entrypoint sh "$IMG" /work/signing/sign-all.sh
# publish the trust anchor where the resolver config includes it
cp signed/trust-anchor.conf configs/resolver/trust-anchor.conf
echo "Signed zones in ./signed ; trust anchor copied to resolver config."
