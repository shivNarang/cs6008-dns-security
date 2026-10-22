# common/signing — DNSSEC signing (shared, frozen)

Signs the three lab zones, chains DS records parent→child, and emits the
resolver's root trust anchor. Used by phases 3, 4, 5, 6.

## Files
- `sign-all.sh` — the signer (runs inside a BIND-tools container).
- `run.sh` — dockerized wrapper: builds the `cs6008-dns-base` image if needed,
  mounts `../base/zones` as input, writes signed output to `./out`.

## Run
```sh
sh run.sh            # NSEC zones (walkable — Phase 5 "before")
NSEC3=1 sh run.sh    # NSEC3 zones (Phase 5 "fixed")
```
Output in `./out/`: `root.signed`, `com.signed`, `example.com.signed`,
per-zone keys (`K*.key`/`K*.private`), `dsset-*`, and `trust-anchor.conf`.
A phase normally signs into its *own* dir — see `phase3/sign.sh`.

## Design
- **Algorithm: ECDSAP256SHA256 (algo 13).** Small keys and signatures, fast
  validation, universally supported. Trade-off vs RSA: shorter history, but the
  modern default; vs Ed25519 (algo 15): slightly more compatible with old validators.
- **Chain of trust:** sign `example.com` → put its KSK's DS in `com` → sign `com`
  → put its KSK's DS in root → sign root. The resolver anchors on the **root KSK**
  (`trust-anchor.conf`, a `static-key`), so one anchor validates the whole tree.
- **Denial of existence:** NSEC by default (lets Phase 5 walk the zone); `NSEC3=1`
  switches to NSEC3 (the Phase 5 fix).
- **Keys are build artifacts** — never committed. The grader reruns the signer.
  No private key belongs in the repo.

## Verified
On Colima: all three zones `dnssec-verify` clean; a validating resolver returns
the **AD flag** + RRSIG for `example.com`, and `delv` reports `; fully validated`
with the root KSK as trust anchor (see `phase3/`).
