# Phase 7: Encrypting the Last Mile (DoT / DoH)

Authenticate and encrypt the client-resolver link, then mount the last-mile attack
again from three angles and account for each result.

Reuses the Phase 3 signed hierarchy; adds TLS on the resolver and a client that
reaches it **by name** over an encrypted, authenticated transport, plus the Phase 6
on-path attacker and a rogue resolver for the attack half.

## Run
```sh
sh scripts/deploy.sh         # CA + certs + signed zones, then start the stack
sh scripts/verify.sh         # DoT + DoH resolve, cert enforced, no cleartext :53
sh scripts/run-attacks.sh    # 7.3: the three attempts x two clients + matrix
docker compose down
```
`pki.sh` makes the CA + resolver cert; `sign.sh` makes the signed zones + trust
anchor. Both write git-ignored artifacts under `pki/out` and `signed`.

## 7.1 Deploy choices
- **Private CA** (`pki/gen-ca.sh`): RSA-2048 root CA; resolver cert CN/SAN =
  `resolver.cs6008.local`, **DNS SAN only, no IP SAN**. Installed into the
  client's system trust store (`update-ca-certificates`), no `-k`/insecure bypass.
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

## 7.3 Attack: three attempts against two client policies

Two client policies (same client box, two resolve scripts in `client-bin/`):

- **strict** (`resolve-strict.sh`): DoT only, cert validated against the lab CA and
  the hostname. If the encrypted transport is not available it fails. Never cleartext.
- **lax** (`resolve-lax.sh`): prefer DoT, but if the encrypted transport cannot be
  reached, fall back to plain :53. A bad certificate is treated as an attack, not an
  unavailable transport, so it does not trigger fallback.

All on-path controls live on `edge-router` (`scripts/net.sh`): `divert` (client :53
through the attacker), `block` (drop TCP 853/443), `dnat-on` (redirect resolver :853
to the rogue resolver).

Measured outcomes (`sh scripts/run-attacks.sh`):

```
================= 7.3 outcome matrix (does the attack land?) =================
 attempt                         | strict (refuses cleartext) | lax (permits cleartext)
---------------------------------+----------------------------+-------------------------
 (i)  alter answer in transit    | no  (TLS integrity)        | no  (TLS integrity)
 (ii) rogue-cert impersonation   | no  (cert not trusted)     | no  (cert not trusted)
 (iii) block transport, downgrade| no, fails closed (DoS)     | YES, forged to rogue
=============================================================================
```

- **(i) alter in transit.** The attacker is on-path and forging, but the DNS is inside
  TLS. The cleartext forge tool sees no :53 to touch, and a capture of 853 has zero
  readable `example.com` strings. Both clients get the real 172.16.1.20.
- **(ii) rogue cert.** `dnat-on` sends the resolver's 853 to a rogue server whose cert
  names `resolver.cs6008.local` but is self-signed, not issued by the lab CA. Both
  clients reject it: `handshake failed (Error in the certificate)`. Neither falls for it.
- **(iii) block + downgrade.** `block` drops 853/443 and `divert` + forge poisons :53.
  Strict gets `connection timeout for ...@853` and no answer: it fails closed. Lax sees
  the transport is down, falls back to :53, and takes the forged `172.16.1.30` (rogue
  HACKED page). This is the only combination that lands.

## 7.4 Report answers

**Each attempt and client (above matrix).** Five of the six combinations fail. The one
that lands, (iii) against lax, does not beat the cryptography: it beats a client policy
that still allows cleartext. With that fallback removed (strict), the same attack only
denies service.

**DoT or DoH, and drawbacks.** We deployed both and lead with DoT. DoT on its own port
853 is simple and easy to audit, and just as easy to spot and block on the network,
which is exactly what made attempt (iii) possible to stage. DoH on 443 blends into
normal HTTPS and is much harder to block, at the cost of being harder to audit and
heavier because of the HTTP/2 framing. The choice is visibility versus blend-in.

**What an encrypted, authenticated last mile still does not protect.** It protects the
client-resolver hop only. It does nothing for the resolver-to-authoritative path, which
is still plain :53 upstream (DNSSEC gives integrity there, not confidentiality). It does
not hide which resolver you talk to, and it does not stop a malicious or misconfigured
resolver from lying to you over a perfectly valid TLS session: the channel is
authenticated, the answer is not. Only client-side DNSSEC validation (Phase 6, Client B)
catches that.

## Commands (reproduce)

```
sh scripts/deploy.sh
sh scripts/verify.sh                 # 7.2 encrypted resolution + no cleartext
sh scripts/attempt1-tamper.sh        # (i)
sh scripts/attempt2-roguecert.sh     # (ii)
sh scripts/attempt3-downgrade.sh     # (iii)
sh scripts/run-attacks.sh            # all three + the matrix
```
