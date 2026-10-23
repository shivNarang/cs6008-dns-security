#!/bin/sh
# Strict client policy: DoT only, certificate validated against the lab CA and the
# hostname. If the encrypted, authenticated transport is not available for any
# reason, it fails. It never falls back to cleartext.
NAME=resolver.cs6008.local
Q="${1:-example.com}"
kdig +tls +tls-hostname="$NAME" +tls-ca @"$NAME" "$Q" A
