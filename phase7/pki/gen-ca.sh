#!/bin/sh
# Private CA + resolver TLS cert (SAN = resolver.cs6008.local, no IP SAN).
# Runs inside the base image (has openssl). Output -> /work/out (gitignored).
set -e
OUT="${OUT:-/work/out}"; mkdir -p "$OUT"; cd "$OUT"
NAME="resolver.cs6008.local"

# 1) Root CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
    -days 3650 -subj "/O=CS6008 Lab/CN=CS6008 Lab Root CA" >/dev/null 2>&1

# 2) Resolver key + CSR
openssl req -newkey rsa:2048 -nodes -keyout resolver.key -out resolver.csr \
    -subj "/O=CS6008 Lab/CN=$NAME" >/dev/null 2>&1

# 3) Sign with SAN = the DNS name only (no IP SAN)
cat > ext.cnf <<X
subjectAltName = DNS:$NAME
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
X
openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out resolver.crt -days 825 -extfile ext.cnf >/dev/null 2>&1

echo ">> CA + resolver cert generated in $OUT"
openssl x509 -in resolver.crt -noout -subject -ext subjectAltName | sed 's/^/   /'

# 4) ROGUE cert for the impersonation attempt: same name, self-signed, NOT the lab CA.
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt \
    -days 825 -subj "/O=Totally Legit/CN=$NAME" \
    -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
echo ">> rogue (untrusted) cert for $NAME generated in $OUT"
