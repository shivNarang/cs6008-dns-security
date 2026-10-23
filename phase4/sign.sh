#!/bin/sh
# Sign the hierarchy for Phase 4 using the shared signer.
#   sh sign.sh                 # Run A: com publishes DS for example.com (secure)
#   NODS="example.com" sh sign.sh   # Run B: com publishes NO DS (insecure delegation)
set -e
cd "$(dirname "$0")"
IMG=cs6008-dns-base
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" ../common/base
mkdir -p signed
docker run --rm -e NSEC3="${NSEC3:-0}" -e NODS="${NODS:-}" \
    -v "$(cd ../common/base/zones && pwd)":/work/zones:ro \
    -v "$(cd ../common/signing && pwd)":/work/signing \
    -v "$(pwd)/signed":/work/out \
    --entrypoint sh "$IMG" /work/signing/sign-all.sh
cp signed/trust-anchor.conf configs/resolver/trust-anchor.conf
echo "Signed zones in ./signed ; trust anchor copied to resolver config."
