# CS6008 Assignment 2: DNS Security

Self-contained DNS hierarchy in Docker: deploy plain DNS, attack it on-path,
then add defenses (DNSSEC, DoT/DoH) one layer at a time.

## Repo layout

- `common/`: shared, frozen foundations that multiple phases reuse:
  - `base/`       : Phase 1 hierarchy: compose, zone files, BIND configs, routing/static-route scripts
  - `signing/`    : DNSSEC signing scripts (produce signed zones for phases 3 to 6)
  - `interceptor/`: C/libpcap interceptor skeleton (relay + forge; extended by phases 2, 4, 6)
- `phase1/` … `phase7/`: one self-contained directory per phase (own compose.yml, configs, scripts, README)
- `report.pdf`: final report, one section per phase (built from each person's section)

## Work split

| Owner        | Phases                | Marks        |
|--------------|-----------------------|--------------|
| Shiv         | 1, 2, 3 + half of 7   | 40 + 7.5     |
| Teammate     | 4, 5, 6 + half of 7   | 40 + 7.5     |

**Phase 7 split:** one person does deploy (private CA, resolver cert, DoT/DoH config);
the other runs the three attack attempts against both client types and writes up the 6 outcomes.

## How we work independently

1. Build `common/base`, `common/signing`, `common/interceptor` **together first**, then freeze.
2. Each person copies the needed `common/` pieces into their own `phaseN/` dirs and works solo.
3. Only re-sync if a `common/` file has a bug.

## Ground rules

- All attack code in **C/C++ with libpcap only** (Scapy / dnspython are banned).
- Commit **sources, configs, scripts only**: never compiled binaries, signed zones, or built images.
- Each `phaseN/` README must let a grader reproduce results on a clean checkout.
- Same DNSSEC signing algorithm across phases 3 to 6 so the chain stays consistent.
- No private keys in the repo.
- Deadline: **23 October 2026**. If AI was used, list prompts + verification in a report appendix.
