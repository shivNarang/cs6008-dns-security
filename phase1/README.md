# Phase 1: Building the DNS Hierarchy

Three-tier hierarchy (root → com → example.com), recursive resolver (DNSSEC
validation OFF), and a webserver, across three isolated subnets joined only by
two no-NAT routers. No attacker. This is the baseline every later phase builds on.

Configs and zones live in `../common/base` (the shared base); this directory just
wires them into the Phase 1 topology.

## Run
```sh
sh scripts/deploy.sh     # build base image if needed, start the 8 containers
sh scripts/verify.sh     # resolution, web fetch, isolation check, resolver route
sh scripts/capture.sh    # capture a full root->tld->domain resolution to resolution.pcap
sh scripts/teardown.sh
```

## 1.2 Verify (expected)
- `dig example.com` / `www.example.com` → **172.16.1.20**; `curl http://example.com` → real page.
- `dig @172.16.3.10 example.com` from client → **no servers could be reached** (auth subnet not directly reachable).
- `ip route get 172.16.3.10` on resolver → **via 172.16.2.3** (core-router).

## Topology & routing
- client 172.16.1.10 · webserver .20 · edge-router .1.2/.2.2 · resolver 172.16.2.10 ·
  core-router .2.3/.3.3 · root-ns 172.16.3.10 · tld-ns .20 · domain-ns .30.
- Isolation is by topology: `internal` bridges (no NAT), cross-subnet only via a
  router attached to both bridges. Static routes per node; only routers forward.

## Verified on Colima
All five checks pass; core-router capture shows the resolver→root→tld→domain referral.
