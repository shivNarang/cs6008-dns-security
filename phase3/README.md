# Phase 3 — DNSSEC Chain of Trust

Signed hierarchy + validating resolver. Reuses the Phase 1 topology; only the
zones (now signed) and the resolver (now validating, root-anchored) change.

## Deploy
```sh
sh scripts/deploy.sh    # signs zones (via common/signing) then starts the stack
sh scripts/verify.sh    # AD flag + delv "fully validated" + web fetch
docker compose down     # stop
```
`sign.sh` regenerates `./signed/*.signed` and `configs/resolver/trust-anchor.conf`
from the unsigned zones in `common/base/zones` — nothing signed is committed.

## What this proves (3.2 Verify)
- `dig +dnssec example.com` → `status: NOERROR`, `flags: ... ad`, with an RRSIG.
- `delv -a trust-anchor.conf` → `; fully validated`.
- Chain: root KSK → DS(com) → com KSK → DS(example.com) → example.com.

## Attack (3.3) — TODO
Re-run the Phase 2 forgery unchanged against this validating resolver and record
that the forged (unsigned) answer is rejected (SERVFAIL / no rogue redirect).
Needs the Phase 2 interceptor (see `common/interceptor`).

## Config notes
- Authoritative servers serve `*.signed` (static signed zones).
- Resolver: `dnssec-validation yes;` + `include "trust-anchor.conf";` (the root KSK
  as a `static-key`); root hints unchanged from Phase 1.
- Algorithm ECDSAP256SHA256 (algo 13). No private keys in the repo.

## Verified on Colima
All three checks pass (AD flag, delv fully validated, web fetch).
