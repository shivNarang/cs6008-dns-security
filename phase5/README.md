# Phase 5: Zone Walking

A signed zone has to prove that a name does *not* exist, and that proof is signed
ahead of time, before anyone knows which name will be asked. A proof prepared in
advance cannot be about the queried name itself, so it reveals something about the
names that *do* exist. With NSEC, what it reveals is the next existing name, and that
is enough to walk the whole zone.

The `example.com` zone here advertises only `example.com` and `www`. Everything else
(`backup`, `dev`, `git`, `mail`, `staging`, `vpn`) is an internal hostname that
appears nowhere public. The attack recovers all of them.

## Deploy

```
sh scripts/deploy.sh      # signs with NSEC (the walkable zone) and brings it up
```

## Verify (5.2)

Ask for a name that does not exist and look at how the zone answers:

```
$ dig +dnssec nope.example.com @172.16.3.30
example.com.       NSEC  backup.example.com. A NS SOA RRSIG NSEC DNSKEY
mail.example.com.  NSEC  ns.example.com.     A RRSIG NSEC
```

The denial is two signed NSEC records, each pointing from one real name to the next.
To prove `nope` does not exist, the server has to hand over the real names on either
side of where `nope` would sort. The proof leaks its neighbours.

## Attack (5.3)

Starting from `example.com` alone, follow the chain: query the apex's NSEC to get the
first name, query that name's NSEC to get the next, and so on until it wraps back to
the apex. One query per name, no AXFR and no wordlist.

```
$ sh scripts/walk.sh
queries sent : 9
names recovered:
  backup.example.com.      10.0.0.5
  dev.example.com.         10.0.0.6
  git.example.com.         10.0.0.7
  mail.example.com.        10.0.0.8
  ns.example.com.          172.16.3.30
  staging.example.com.     10.0.0.9
  vpn.example.com.         10.0.0.10
  www.example.com.         172.16.1.20
```

Nine names recovered in nine queries, within the (number of names + 2) budget.

### Fix

```
sh scripts/fix.sh        # re-sign with NSEC3, reload, re-run the same walk
```

```
re-run the same walk: no NSEC returned -> names recovered: (none)
denial still authenticated: ...NSEC3 1 0 0 75E10D3A... (signed)
```

The walker is unchanged; it just finds no NSEC chain to follow, and a nonexistent name
still gets an authenticated denial, now via NSEC3.

## Report answers

**Names recovered and how.** The six internal names above plus `ns` and `www`,
recovered by following the NSEC chain with the C/libpcap walker (`walker/zonewalk.c`):
it injects raw NSEC queries with `pcap_inject` and captures responses with libpcap.
An NSEC query on the apex returns `backup` as the next name, querying `backup` returns `dev`,
and so on through `git, mail, ns, staging, vpn, www` back to the apex.

**What made the walk possible, and why signed denial leaks when plain DNS does not.**
NSEC made it possible. Plain DNS answers a nonexistent name with an unsigned NXDOMAIN
that says nothing about other names, and it is generated on demand. DNSSEC cannot sign
on demand without the online private key it is designed to avoid, so denial is
precomputed: for every gap between two adjacent existing names it signs one NSEC record
that spans that gap. Those records chain every existing name to the next, and reading
them back in order reconstructs the zone.

**What the fix costs, and what an enumerator can still learn.** NSEC3 hashes the owner
names before chaining them, so the online walk returns only hashes, not names. It costs
the operator more: extra records and signatures (larger zone, more signing and
validation work), and the hashing is not secrecy. An enumerator can still count the
NSEC3 records to learn how many names exist, and can take the hashes offline and run a
dictionary or brute-force attack against them to recover guessable names (short or
common labels fall quickly), which is why a salt and, where the tradeoff is acceptable,
NSEC3 opt-out or minimally-covering responses matter. The clean fix for truly secret
names is not to put them in public DNS at all.

## Commands (reproduce)

```
sh scripts/deploy.sh                    # NSEC zone up
sh scripts/verify.sh                    # 5.2 signed NXDOMAIN reveals neighbours
sh scripts/walk.sh                      # 5.3 recover every name
sh scripts/fix.sh                       # re-sign NSEC3, walk recovers nothing

# the walk, run by hand inside the walker node:
docker exec walker /opt/walker/zonewalk -i eth0 -s 172.16.3.30 -g 172.16.2.3 -S 172.16.2.100 -z example.com
```

Walker source: `walker/zonewalk.c` (written in C with libpcap: injects raw queries and captures replies; no Scapy/dnspython/dig).
