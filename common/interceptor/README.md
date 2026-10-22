# common/interceptor — on-path DNS interceptor (shared, frozen)

C + libpcap engine used by Phase 2 (forge), Phase 4 (strip/downgrade), and
Phase 6 (last-mile). Captures the diverted victim-bound DNS responses, relays
them transparently, and in `forge` mode rewrites the A answer for one name.

## How the diversion works (not done by this program)
A route on the **router** sends the victim's inbound DNS responses to the
attacker at L2. The attacker does **not** ip_forward; the kernel would drop
those frames, so we `pcap_open_live` + `pcap_inject` to relay them on — exactly
the capture+inject libpcap path the brief requires.

## Build & run
```sh
make                       # -> ./dns_intercept   (needs libpcap-dev)
# victim MAC comes from /proc/net/arp, so ping the victim once first:
ping -c1 172.16.2.10
./dns_intercept -i eth0 -v 172.16.2.10 -t example.com -r 172.16.1.30 -m relay
./dns_intercept -i eth0 -v 172.16.2.10 -t example.com -r 172.16.1.30 -m forge
```
- `-v` victim (whose replies are diverted to us) `-t` name to hijack
- `-r` rogue A rdata `-m relay|forge`
- BPF filter selects only `ether dst <us> and udp src port 53 and dst <victim>`,
  so our own injected frames (dst = victim MAC) are never recaptured — no loop.

## forge logic
Only the **exact** target name with `QTYPE=A` is touched; `www.<target>` and all
other names are relayed byte-for-byte. The A rdata (4 bytes) is overwritten in
place and IP+UDP checksums are recomputed — packet length is unchanged.

## Extension hooks (for the other phases)
- **Phase 4 (strip):** in `forge_or_relay()`, drop `RRSIG`(46)/`DNSKEY`(48)
  records and fix the header counts to make the signed zone look unsigned.
- **Phase 6 (last-mile):** same engine, but the diversion is on the *edge* router
  and the victim is the **client** (`-v 172.16.1.10`); forge the resolver→client reply.

## Verified on Colima
relay mode: `example.com` still resolves to 172.16.1.20.
forge mode: `example.com` -> 172.16.1.30 (rogue) while `www.example.com` stays 172.16.1.20.
