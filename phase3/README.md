# Phase 3: DNSSEC Chain of Trust

Signed hierarchy + validating resolver. Reuses the Phase 1 topology; only the
zones (now signed) and the resolver (now validating, root-anchored) change.

## Deploy & Attack
```sh
sh scripts/deploy.sh    # signs zones (via common/signing) then starts the stack
sh scripts/verify.sh    # 3.2: AD flag + delv "fully validated" + web fetch
sh scripts/attack.sh    # 3.3: re-run Phase 2 forgery -> SERVFAIL
docker compose down     # stop
```
`sign.sh` regenerates `./signed/*.signed` and `configs/resolver/trust-anchor.conf`
from the unsigned zones in `common/base/zones`, nothing signed is committed.

## What this proves (3.2 Verify)
- `dig +dnssec example.com` → `status: NOERROR`, `flags: ... ad`, with an RRSIG.
- `delv -a trust-anchor.conf` → `; fully validated`.
- Chain: root KSK → DS(com) → com KSK → DS(example.com) → example.com.

## Attack (3.3)
```sh
sh scripts/attack.sh
```
Re-runs the Phase 2 forgery unchanged against this validating resolver by diverting
traffic through the attacker on core-router and flushing the resolver cache:
- `dig example.com` → `status: SERVFAIL`, `ANSWER: 0`.
- Resolver log: `RRSIG failed to verify resolving 'example.com/A/IN': 172.16.3.30#53`.
- `curl http://example.com` fails to connect / cannot resolve to rogue.

## Config notes
- Authoritative servers serve `*.signed` (static signed zones).
- Resolver: `dnssec-validation yes;` + `include "trust-anchor.conf";` (the root KSK
  as a `static-key`); root hints unchanged from Phase 1.
- Algorithm ECDSAP256SHA256 (algo 13). No private keys in the repo.

## Verified on Colima
- Verification: AD flag, delv fully validated, web fetch all pass.
- Attack: re-run Phase 2 forgery is rejected with SERVFAIL; resolver logs RRSIG verification failure.
