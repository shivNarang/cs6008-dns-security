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

## Status

All seven phases are built and verified end to end on Docker (Colima). Each
`phaseN/` is self-contained: `scripts/deploy.sh` brings it up and
`scripts/verify.sh` / the attack scripts reproduce the results in that phase's
README.

| Phase | Topic                          | Marks |
|-------|--------------------------------|-------|
| 1     | Build the hierarchy            | 10    |
| 2     | On-path response forgery       | 15    |
| 3     | DNSSEC chain of trust          | 15    |
| 4     | Signature stripping / downgrade| 15    |
| 5     | Zone walking                   | 10    |
| 6     | Last-mile forgery              | 15    |
| 7     | DoT / DoH + the three attacks  | 15    |

## How the pieces fit

1. `common/base`, `common/signing`, `common/interceptor` are the shared, frozen
   foundations.
2. Each `phaseN/` reuses them through mounts and its own compose, configs, and
   scripts, so a phase can be deployed and graded on its own.

## Ground rules

- All attack code in **C/C++ with libpcap only** (Scapy / dnspython are banned).
- Commit **sources, configs, scripts only**: never compiled binaries, signed zones, or built images.
- Each `phaseN/` README must let a grader reproduce results on a clean checkout.
- Same DNSSEC signing algorithm across phases 3 to 6 so the chain stays consistent.
- No private keys in the repo.
- Deadline: **23 October 2026**. If AI was used, list prompts + verification in a report appendix.

## Packaging for submission

The brief requires submitting one Git repository archived as a single `.zip` or `.tar.gz` (keeping the `.git` history inside), with no generated artifacts or private keys included:

```sh
# 1. Ensure report.pdf is built
sh make-report.sh

# 2. Clean any generated artifacts (signed zones, keys, certificates)
git clean -fdX

# 3. Create the submission archive (preserves .git history)
tar -czf ../CS6008_AS2_submission.tar.gz .
# or: zip -r ../CS6008_AS2_submission.zip .
```
