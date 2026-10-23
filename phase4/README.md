# Phase 4: Signature Stripping and Downgrade

Forging a signed answer failed in Phase 3. Here the attacker instead tries to make
the signed zone look *unsigned*, so the plain Phase 2 forgery is accepted again.
The attacker rewrites traffic but holds no private keys.

Same signed hierarchy and validating resolver as Phase 3. The attacker runs the
shared interceptor in a new **strip** mode: for `example.com` it rewrites the A to
`rogue-web` and then cuts the message off right after that record, so the RRSIG and
every other DNSSEC record is gone. The resolver is handed a bare, unsigned-looking
A.

## Deploy

```
sh scripts/run-a.sh     # Run A: com publishes a DS for example.com (secure)
sh scripts/run-b.sh     # Run B: com publishes NO DS (insecure delegation)
```

Each script re-signs, brings the stack up on a clean cache, shows the baseline, then
diverts the resolver's inbound responses through the attacker and retries. The only
difference between the two is one line in the signer (`NODS="example.com"`), which
tells `com` not to publish the DS.

## Verify (before stripping)

Run A baseline: `example.com` resolves with the `ad` flag (authenticated).
Run B baseline: `example.com` resolves NOERROR but with **no** `ad` flag, because the
missing DS makes it an insecure delegation that the resolver does not authenticate.

## Attack

**Run A (DS present).** The strip lands a forged, unsigned A, but the resolver knows
from the DS in `com` that `example.com` is signed. A zone that should be signed now
has no signature and no authenticated proof that it went insecure, so validation
fails:

```
status: SERVFAIL
resolver: insecurity proof failed resolving 'example.com/A/IN': 172.16.3.30#53
```

**Run B (no DS).** The operator signed the child but never gave `com` the DS.
`com` is still signed, and it now carries a signed NSEC proving that no DS exists for
`example.com`, so the resolver legitimately concludes the zone is insecure, skips
signature checking, and accepts the forged A:

```
example.com -> 172.16.1.30      (rogue "HACKED" page)
```

## Report answers

In Run A the signatures, and even the DS, can be stripped on the wire, but the
attacker cannot make the zone look unsigned. "Unsigned" is not the absence of
signatures, it is a *signed* statement by the parent that the child has no DS. The
parent `com` still says, with a signature the attacker cannot forge, that
`example.com` has a DS and is therefore secure. Faced with an unsigned answer for a
name that must be signed, the resolver returns SERVFAIL rather than trust it.

In Run B the single change is removing `example.com`'s DS from `com`. That flips the
parent's signed statement from "this child is secure" to "this child is insecure",
and the resolver believes it because it is authenticated. From then on `example.com`
is treated as plain DNS and the Phase 2 forgery works again.

So downgrade resistance does not come from the child being signed. It comes from the
**secure delegation**: the DS in the parent, chained to the trust anchor. The exact
operator mistake that forfeits it is signing a zone but never publishing (or later
dropping) its DS in the parent. The zone looks signed from the inside and is wide
open to downgrade from the outside.

## Commands (reproduce)

```
sh scripts/run-a.sh       # full Run A (secure delegation -> SERVFAIL)
sh scripts/run-b.sh       # full Run B (insecure delegation -> rogue)

# the one-line difference, visible in the signer:
NODS="" sh sign.sh                 # Run A signing
NODS="example.com" sh sign.sh      # Run B signing

# manual: confirm com has no DS for example.com in Run B
docker exec client dig +norec @172.16.3.20 example.com DS

sh scripts/divert.sh / undivert.sh / flush.sh    # diversion + cache controls
```

Attacker source and the strip mode: `common/interceptor/dns_intercept.c`
(mode `strip`, see `handle_dns()`).
