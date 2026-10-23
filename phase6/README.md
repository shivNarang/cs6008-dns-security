# Phase 6: Last-Mile Response Forgery

The resolver validates, but the link from resolver to client carries no proof of it.
A stub trusts whatever appears to come from its resolver. So we move the attacker onto
the client subnet and forge the reply on the last hop, where DNSSEC's guarantee runs
out.

Upstream is the Phase 3 signed, validating resolver, untouched. The attacker is on the
client subnet at `172.16.1.100`. A route on `edge-router` (not ARP spoofing) sends a
client's inbound replies via the attacker, which relays or forges them. The client's
own configuration is untouched.

Two victims:

- **client-a** (`172.16.1.10`): an ordinary stub using the OS resolver and `curl`. No
  local validation.
- **client-b** (`172.16.1.11`): a locally validating client that holds the root KSK as
  its own trust anchor and checks signatures itself with `delv`.

## Deploy

```
sh scripts/deploy.sh
```

## Verify (6.2)

With the attacker relaying, resolution is transparent:

```
client-a example.com -> 172.16.1.20   ("Welcome to example.com")
```

## Attack (6.3)

**Client A.** Forge the resolver to client reply for `example.com`:

```
$ sh scripts/attack-a.sh
client-a example.com      -> 172.16.1.30   (rogue "HACKED" page)
client-a www.example.com  -> 172.16.1.20   (untargeted, untouched)
```

The stub takes the forged A and connects to the rogue server. The upstream answer was
validated by the resolver, which does not help: the forgery happens after the resolver,
on a hop that carries no signatures the stub checks.

**Client B.** Same forgery, but client-b validates the answer itself:

```
$ sh scripts/attack-b.sh
plain dig on client-b  -> 172.16.1.30                 (would be fooled)
delv on client-b       -> RRSIG failed to verify
                          resolution failed: RRSIG failed to verify
```

A plain `dig` on the same machine accepts the forgery, so the difference is not the
network, it is that `delv` fetches the signatures and checks them against its own root
anchor. The forged A is not covered by any valid signature, so it is rejected.

## Report answers

**DNSSEC validates upstream, so why does it not stop this?** Because validation happens
at the resolver, and trust is placed by the stub. The resolver validated the real answer
and set the `ad` flag, but `ad` is just a bit in a cleartext packet on the last hop. The
attacker rewrites the answer (and can set `ad` at will) after the resolver, and the stub
has no signature to check, so it believes the bit. DNSSEC protects the data from the
authoritative server to whoever actually validates it; here that is the resolver, and the
resolver to stub hop is outside that protection.

**What tells a stub its answer was validated, and why can an on-path attacker set it?**
The `ad` (authenticated data) flag. It is one bit in the plaintext DNS header on the
resolver to client link, with nothing signing it, so an on-path attacker sets it on a
forged reply for free. Client B does not rely on `ad`: it runs its own validation against
a trust anchor it holds, so it needs real signatures, which the attacker cannot produce.

**Where does protection actually come from?** From validation happening where trust is
placed. Moving validation onto the client (a validating stub, or `delv` as here) closes
the last mile. The other way to close it is to authenticate and encrypt the hop itself,
which is Phase 7.

## Commands (reproduce)

```
sh scripts/deploy.sh                 # bring up signed upstream + both clients + attacker
sh scripts/verify.sh                 # 6.2 relay is transparent
sh scripts/attack-a.sh               # 6.3 Client A lands on the rogue page
sh scripts/attack-b.sh               # 6.3 Client B (delv) rejects the forgery

sh scripts/divert.sh <client-ip>     # route on edge-router only
sh scripts/undivert.sh               # remove diversion
```

Attacker source: `common/interceptor/dns_intercept.c` (mode `forge`, victim = the
client).
