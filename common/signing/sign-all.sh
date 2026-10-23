#!/bin/sh
# Generate DNSSEC keys, sign the three lab zones, chain DS records parent->child,
# and emit the resolver's root trust anchor. Runs inside a container that has
# BIND's dnssec-* tools (see run.sh). Private keys and signed zones are build
# artifacts (git-ignored); the grader regenerates them from this script.
#
# Env knobs:
#   ALGO  : signing algorithm         (default ECDSAP256SHA256 = algo 13)
#   NSEC3 : 1 => NSEC3 denial of existence (Phase 5 "fixed" zone); default NSEC
#   NODS  : space-separated child zones whose DS we DO NOT publish in the parent.
#           "example.com" => com is signed but gives no DS for it, so a validator
#           treats example.com as an insecure (unsigned) delegation. Phase 4 Run B.
set -eu

ZONEDIR="${ZONEDIR:-/work/zones}"     # unsigned zone files (input)
OUT="${OUT:-/work/out}"               # signed zones + keys + anchor (output)
ALGO="${ALGO:-ECDSAP256SHA256}"
NSEC3="${NSEC3:-0}"
NODS="${NODS:-}"

mkdir -p "$OUT"; find "$OUT" -mindepth 1 -delete 2>/dev/null || true; cd "$OUT"

nsec3flags=""
if [ "$NSEC3" = "1" ]; then
    # random 8-byte salt, 0 extra iterations (modern best practice)
    salt=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    nsec3flags="-3 $salt -H 0"
    echo ">> denial of existence: NSEC3 (salt=$salt)"
else
    echo ">> denial of existence: NSEC (walkable - Phase 5 'before' zone)"
fi

keygen() {  # keygen <zone>
    z="$1"
    dnssec-keygen -a "$ALGO" -f KSK -n ZONE "$z" >/dev/null
    dnssec-keygen -a "$ALGO"        -n ZONE "$z" >/dev/null
}

ds_of() {   # ds_of <zone>  -> prints DS record(s) for that zone's KSK
    z="$1"
    for k in K"$z".*.key; do
        if grep -q "DNSKEY 257 " "$k"; then
            dnssec-dsfromkey -2 "$k"
        fi
    done
}

sign() {    # sign <zone> <input-zonefile>
    z="$1"; infile="$2"
    out=$(signed_name "$z")
    cp "$infile" "./in.$out"
    # smart-sign (-S): pull this zone's keys from -K, add DNSKEYs automatically
    dnssec-signzone -S -K "$OUT" -o "$z" $nsec3flags \
        -N increment -f "$OUT/$out" "./in.$out" >/dev/null
    dnssec-verify -o "$z" "$OUT/$out" >/dev/null && echo ">> signed + verified: $z  -> $out"
}

signed_name() {  # map zone origin to a safe output filename
    case "$1" in
        .) echo "root.signed" ;;
        *) echo "$1.signed" ;;
    esac
}

echo "== generating keys (algo $ALGO) =="
keygen example.com
keygen com
keygen .

echo "== sign child first, then chain DS upward =="
# 1) example.com (leaf)
sign example.com "$ZONEDIR/example.com.zone"

# 2) com = base com zone + DS(example.com), then sign.
#    If example.com is listed in NODS we skip its DS, leaving an insecure
#    delegation (signed proof of "no DS" is generated automatically). Run B.
cp "$ZONEDIR/com.zone" com.work
case " $NODS " in
    *" example.com "*)
        echo ">> NODS: com will publish NO DS for example.com (insecure delegation)" ;;
    *)
        echo "; --- DS of example.com (chain of trust) ---" >> com.work
        ds_of example.com >> com.work ;;
esac
sign com com.work

# 3) root = base root zone + DS(com), then sign
cp "$ZONEDIR/root.zone" root.work
echo "; --- DS of com (chain of trust) ---" >> root.work
ds_of com >> root.work
sign . root.work

echo "== build resolver trust anchor from the ROOT KSK =="
rootksk=$(for k in K.+*.key; do grep -q "DNSKEY 257 " "$k" && echo "$k"; done | head -1)
# DNSKEY line: ".  IN DNSKEY 257 3 13 <base64...>"  -> static-key
keymat=$(grep "DNSKEY 257 " "$rootksk" | sed -E 's/.*DNSKEY[[:space:]]+257[[:space:]]+3[[:space:]]+[0-9]+[[:space:]]+//' | tr -d ' ')
algonum=$(grep "DNSKEY 257 " "$rootksk" | sed -E 's/.*DNSKEY[[:space:]]+257[[:space:]]+3[[:space:]]+([0-9]+)[[:space:]]+.*/\1/')
cat > "$OUT/trust-anchor.conf" <<ANCHOR
// Root trust anchor (root KSK) for the validating resolver.
trust-anchors {
    "." static-key 257 3 $algonum "$keymat";
};
ANCHOR
echo ">> wrote trust-anchor.conf (root KSK, algo $algonum)"

echo
echo "== DONE =="
ls -1 "$OUT"/root.signed "$OUT"/com.signed "$OUT"/example.com.signed "$OUT"/trust-anchor.conf
