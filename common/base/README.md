# common/base: Phase 1 hierarchy (shared, frozen)

Plain hierarchical DNS in Docker: 3 isolated subnets, 2 routers (the only path
between them, IP-forwarding, **no NAT**), BIND 9.20 everywhere. No attacker.
Every later phase copies this directory and adds to it.

## Layout
- `Dockerfile` / `entrypoint.sh`: all-purpose node image (BIND 9.20, dig/delv,
  iproute2, tcpdump). Entrypoint installs static routes, enables forwarding on
  routers, and pins the client's stub resolver.
- `compose.yml`: the 8 containers + 3 bridges at their fixed addresses.
- `configs/<node>/named.conf`: per-node BIND config; `zones/*.zone`, zone data.
- `configs/resolver/`: recursive config, root hints (`db.root`), `rndc.key` (for cache flush).
- `www/index.html`: the real example.com page.
- `scripts/`: `deploy.sh`, `verify.sh`, `capture.sh`, `teardown.sh`.

## Topology
| node        | subnet            | address        |
|-------------|-------------------|----------------|
| client      | client 1.0/24     | 172.16.1.10    |
| webserver   | client            | 172.16.1.20    |
| edge-router | client + resolver | .1.2 / .2.2    |
| resolver    | resolver 2.0/24   | 172.16.2.10    |
| core-router | resolver + auth   | .2.3 / .3.3    |
| root-ns     | auth 3.0/24       | 172.16.3.10    |
| tld-ns      | auth              | 172.16.3.20    |
| domain-ns   | auth              | 172.16.3.30    |

## Run
```sh
sh scripts/deploy.sh     # build + start
sh scripts/verify.sh     # resolution, web fetch, isolation check, route check
sh scripts/capture.sh    # capture a full root->tld->domain resolution to resolution.pcap
sh scripts/teardown.sh   # stop + remove
```

## How it works (the important bits)
- **Isolation comes from topology.** Each bridge is `internal: true` (no NAT, no
  Internet). A subnet reaches another only through a router that is attached to
  both bridges, forwarding happens *inside* the router container, so Docker's
  own inter-bridge isolation never applies.
- **Static routes** (installed per node via `STATIC_ROUTES`): client→resolver net
  via edge-router; resolver→auth via core-router and resolver→client via
  edge-router; each nameserver→resolver net via core-router. Routers hold both
  connected subnets, so they need no extra routes.
- **Client uses our resolver only**: `RESOLV_NS` rewrites `/etc/resolv.conf` to
  172.16.2.10, backed by the compose `dns:` key.
- The resolver is recursive with **DNSSEC validation OFF** (Phase 1 baseline).

## Notes for graders / teammates
- Needs Docker Engine/Desktop with Compose + Buildx, and the `NET_ADMIN`
  capability (granted in compose). Build needs Internet once; runtime is offline.
- **Verified** on Colima (Docker 29, Ubuntu 24.04 VM, Apple Silicon): all Phase 1
  checks pass, example.com and www resolve to 172.16.1.20, the real page is
  fetched, the direct-to-root query is blocked ("no servers could be reached"),
  and a core-router capture shows the full resolver→root→tld→domain referral.
