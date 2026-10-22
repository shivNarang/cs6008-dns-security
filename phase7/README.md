# Phase 7 — Encrypting the Last Mile (DoT / DoH)  [deploy half]

**Split:** this directory is the *deploy + encrypted-resolution* half of Phase 7
(private CA, resolver cert, DoT/DoH, "no cleartext" verification). The three
**attack** attempts (7.3: alter-in-transit, rogue cert, block-transport × two
clients) build on the Phase 6 last-mile attacker and are the paired half.

Reuses the Phase 3 signed hierarchy; adds TLS on the resolver and a client that
reaches it **by name** over an encrypted, authenticated transport.

## Run
```sh
sh scripts/deploy.sh    # CA + cert + signed zones, then start the stack
sh scripts/verify.sh    # DoT + DoH resolve, cert enforced, no cleartext :53
docker compose down
```
`pki.sh` makes the CA + resolver cert; `sign.sh` makes the signed zones + trust
anchor. Both write git-ignored artifacts under `pki/out` and `signed`.

## 7.1 Deploy choices
- **Private CA** (`pki/gen-ca.sh`): RSA-2048 root CA; resolver cert CN/SAN =
  `resolver.cs6008.local`, **DNS SAN only, no IP SAN**. Installed into the
  client's system trust store (`update-ca-certificates`) — no `-k`/insecure bypass.
- **Reach by name:** client has `extra_hosts: resolver.cs6008.local -> 172.16.2.10`
  and connects to that name; TLS is validated against the hostname, not an IP.
- **Transport:** BIND `tls local-tls { cert-file; key-file; }` with
  `listen-on port 853 tls` (DoT) and `listen-on port 443 tls ... http` (DoH).
  Plain :53 stays up so the block-transport attack has a fallback to target.

## 7.2 Verified on Colima
- DoT: `TLS1.3`, `status: NOERROR`, `ad` flag, answer 172.16.1.20, `@853(TLS)`.
- DoH: `HTTP/2-POST .../dns-query status: 200`, `@443(HTTPS)`.
- **Enforced:** wrong `+tls-hostname` → `handshake failed (Error in the certificate)`;
  missing CA → fails. No silent bypass.
- **No cleartext:** edge-router capture during a DoT lookup = 0 packets on :53,
  31 on :853.

## Which transport & why (7.4, short)
Deployed **both**, lead with DoT. DoT (dedicated 853) is simple and easy to see/
block on the network; DoH (443, looks like HTTPS) is harder to block but harder to
audit and heavier (HTTP/2 framing). Trade-off is visibility vs. blend-in.

## Still protects nothing beyond the last mile
Encrypts/authenticates **client↔resolver** only. It does not protect the
resolver↔auth path (still plain 53 upstream — DNSSEC covers integrity there, not
confidentiality), and it does not hide which resolver you use or stop a malicious
resolver from lying (that's what the client-side DNSSEC validation in Phase 6
Client B is for).
