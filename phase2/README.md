# Phase 2: On-Path Response Forgery

Phase 1 hierarchy + `rogue-web` (172.16.1.30) + `attacker` (172.16.2.100) running
the shared libpcap interceptor (`common/interceptor`). A routing diversion on the
**core-router** sends the resolver's inbound responses through the attacker.

## Run
```sh
sh scripts/deploy.sh    # start stack (relay mode) + turn on the diversion
sh scripts/verify.sh    # 2.2: relaying transparently -> example.com = 172.16.1.20, real page
sh scripts/attack.sh    # 2.3: forge -> example.com = 172.16.1.30 (rogue), www stays 172.16.1.20
docker compose down
```
Toggle pieces by hand: `scripts/divert.sh` / `scripts/undivert.sh` (the route on
core-router only), `scripts/flush.sh` (resolver cache).

## Mechanism
- **Diversion (router only):** `ip route replace 172.16.2.10/32 via 172.16.2.100`
  on core-router. The resolver and nameservers keep their Phase 1 config.
- **Attacker:** holds `NET_RAW` (libpcap) + `NET_ADMIN`. It does **not** ip_forward;
  the kernel drops the diverted frames, so the interceptor captures them and
  `pcap_inject`s them onward, relaying everything, forging only `example.com` A.
- **Why www is safe:** the interceptor matches the *exact* QNAME + `QTYPE=A`, so
  `www.example.com` is relayed byte-for-byte.

## Verified on Colima
- relay: `example.com` -> 172.16.1.20, real "Welcome" page.
- forge: `example.com` -> 172.16.1.30, rogue "HACKED" page; `www.example.com` -> 172.16.1.20.

## Report answers (2.4)
Why it works (plain DNS has no origin authentication; the on-path attacker *sees*
the query so it needs no QID/port guessing, unlike an off-path spoofer), plus the
annotated capture of interception+injection. See the shared interceptor source.
