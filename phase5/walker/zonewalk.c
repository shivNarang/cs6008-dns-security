/*
 * zonewalk.c : NSEC zone-walker over libpcap (capture + inject).
 *
 * CS6008 Assignment 2, Phase 5. The brief requires the zone-walker, like the
 * on-path tools, to be C/C++ using libpcap for both capture and injection (no
 * dig, no Scapy/dnspython). So this builds each DNS query by hand, injects it
 * with pcap_inject, and reads the reply off the wire with libpcap.
 *
 * The walk: ask the authoritative server for a name's NSEC record. Its rdata
 * starts with the next existing owner name in canonical order, so following that
 * chain from the apex recovers every name, one query each, until it wraps back to
 * the apex. If the zone is NSEC3-signed the answer carries no NSEC to follow and
 * the walk recovers nothing.
 *
 * Build: make      Run: ./zonewalk -i eth0 -s 172.16.3.30 -g 172.16.2.3 \
 *                                    -S 172.16.2.100 -z example.com
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

static char     g_iface[64] = "eth0";
static uint32_t g_server, g_src;              /* auth server + our IP (net order) */
static uint8_t  g_mymac[6], g_gwmac[6];       /* our NIC + next-hop (gateway) MAC */
static uint16_t g_sport = 34567;              /* fixed UDP source port            */
static pcap_t  *g_pcap;
static long     g_queries = 0;                /* NSEC queries sent for the walk   */

/* ---- checksums ---- */
static uint16_t cksum16(const uint16_t *p, int len, uint32_t sum)
{
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ---- names ---- */
/* encode "a.b.c" into wire labels at out; return bytes written */
static int encode_name(const char *name, uint8_t *out)
{
    int o = 0; const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len > 63) return -1;
        out[o++] = (uint8_t)len;
        memcpy(out + o, p, len); o += len;
        if (!dot) break;
        p = dot + 1;
    }
    out[o++] = 0;
    return o;
}

/* read a (possibly compressed) name into dotted, lowercased out; advance *p */
static int read_name(const uint8_t *base, const uint8_t *end,
                     const uint8_t **p, char *out, size_t outsz)
{
    size_t o = 0; int jumped = 0; const uint8_t *q = *p, *after = NULL;
    while (q < end) {
        uint8_t len = *q;
        if ((len & 0xc0) == 0xc0) {
            if (q + 1 >= end) return -1;
            if (!jumped) after = q + 2;
            q = base + (((len & 0x3f) << 8) | q[1]); jumped = 1;
            if (q >= end) return -1;
            continue;
        }
        if (len == 0) { q++; break; }
        if (len > 63 || q + 1 + len > end) return -1;
        for (int i = 0; i < len; i++) {
            char c = (char)q[1 + i]; if (c >= 'A' && c <= 'Z') c += 32;
            if (o + 1 < outsz) out[o++] = c;
        }
        if (o + 1 < outsz) out[o++] = '.';
        q += 1 + len;
    }
    if (o > 0 && out[o - 1] == '.') o--;
    out[o] = '\0';
    *p = jumped ? after : q;
    return 0;
}

static const uint8_t *skip_name(const uint8_t *end, const uint8_t *p)
{
    while (p < end) {
        uint8_t len = *p;
        if ((len & 0xc0) == 0xc0) return p + 2;
        if (len == 0) return p + 1;
        p += 1 + len;
    }
    return end;
}

struct dnshdr { uint16_t id, flags, qd, an, ns, ar; };

/* Build an Ethernet+IP+UDP+DNS query (type qtype for qname, EDNS DO set) into
 * buf; return total frame length, or -1 on error. */
static int build_query(uint8_t *buf, const char *qname, uint16_t qtype, uint16_t txid)
{
    struct ether_header *eth = (struct ether_header *)buf;
    memcpy(eth->ether_dhost, g_gwmac, 6);
    memcpy(eth->ether_shost, g_mymac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *ip4 = (struct ip *)(buf + sizeof *eth);
    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip4 + sizeof *ip4);
    uint8_t *dns = (uint8_t *)udp + sizeof *udp;

    /* DNS: header + question + OPT */
    struct dnshdr *h = (struct dnshdr *)dns;
    h->id = htons(txid); h->flags = htons(0x0000);  /* standard query, RD=0 */
    h->qd = htons(1); h->an = 0; h->ns = 0; h->ar = htons(1);
    uint8_t *q = dns + sizeof *h;
    int nl = encode_name(qname, q); if (nl < 0) return -1;
    q += nl;
    *(uint16_t *)q = htons(qtype); q += 2;          /* QTYPE */
    *(uint16_t *)q = htons(1);     q += 2;          /* QCLASS IN */
    /* OPT pseudo-RR with DO bit so we get DNSSEC records */
    *q++ = 0x00;                                    /* root name */
    *(uint16_t *)q = htons(41);   q += 2;           /* type OPT */
    *(uint16_t *)q = htons(4096); q += 2;           /* UDP payload size */
    *(uint32_t *)q = htonl(0x00008000);  q += 4;    /* TTL: DO bit set */
    *(uint16_t *)q = htons(0);    q += 2;           /* rdlen 0 */
    int dlen = (int)(q - dns);

    int udp_len = sizeof *udp + dlen;
    udp->uh_sport = htons(g_sport); udp->uh_dport = htons(53);
    udp->uh_ulen = htons(udp_len); udp->uh_sum = 0;

    memset(ip4, 0, sizeof *ip4);
    ip4->ip_hl = 5; ip4->ip_v = 4; ip4->ip_ttl = 64; ip4->ip_p = IPPROTO_UDP;
    ip4->ip_len = htons(sizeof *ip4 + udp_len);
    ip4->ip_id = htons(txid);
    ip4->ip_src.s_addr = g_src; ip4->ip_dst.s_addr = g_server;
    ip4->ip_sum = cksum16((uint16_t *)ip4, sizeof *ip4, 0);

    /* UDP checksum with pseudo-header */
    uint32_t sum = 0;
    sum += (g_src >> 16) & 0xffff; sum += g_src & 0xffff;
    sum += (g_server >> 16) & 0xffff; sum += g_server & 0xffff;
    sum += htons(IPPROTO_UDP); sum += htons((uint16_t)udp_len);
    udp->uh_sum = cksum16((uint16_t *)udp, udp_len, sum);
    if (udp->uh_sum == 0) udp->uh_sum = 0xffff;

    return (int)(sizeof *eth + sizeof *ip4 + udp_len);
}

/* Send query, capture the matching reply into resp (size rsz). Return DNS
 * payload length, or -1 on timeout. Retransmits a few times. */
static int query(const char *qname, uint16_t qtype, uint8_t *resp, int rsz)
{
    uint8_t frame[1500];
    uint16_t txid = (uint16_t)(rand() & 0xffff);
    int flen = build_query(frame, qname, qtype, txid);
    if (flen < 0) return -1;

    for (int tries = 0; tries < 4; tries++) {
        if (pcap_inject(g_pcap, frame, flen) < 0) {
            fprintf(stderr, "inject: %s\n", pcap_geterr(g_pcap)); return -1;
        }
        struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            struct pcap_pkthdr *hdr; const u_char *bytes;
            int r = pcap_next_ex(g_pcap, &hdr, &bytes);
            if (r == 1) {
                const uint8_t *ip = bytes + sizeof(struct ether_header);
                const struct ip *ip4 = (const struct ip *)ip;
                int ihl = ip4->ip_hl * 4;
                const struct udphdr *udp = (const struct udphdr *)(ip + ihl);
                const uint8_t *dns = (const uint8_t *)udp + sizeof *udp;
                int dlen = ntohs(udp->uh_ulen) - sizeof *udp;
                if (dlen < (int)sizeof(struct dnshdr)) continue;
                if (ntohs(((const struct dnshdr *)dns)->id) != txid) continue;
                if (dlen > rsz) dlen = rsz;
                memcpy(resp, dns, dlen);
                return dlen;
            }
            struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
            if ((t1.tv_sec - t0.tv_sec) * 1000 +
                (t1.tv_nsec - t0.tv_nsec) / 1000000 > 700) break;  /* retransmit */
        }
    }
    return -1;
}

/* From a response, return the next owner name carried in the first NSEC record
 * (answer or authority). Returns 0 and fills next[] on success, -1 otherwise. */
static int nsec_next(const uint8_t *dns, int dlen, char *next, size_t nsz)
{
    const uint8_t *base = dns, *end = dns + dlen;
    const uint8_t *p = dns + sizeof(struct dnshdr);
    const struct dnshdr *h = (const struct dnshdr *)dns;
    int qd = ntohs(h->qd);
    int total = ntohs(h->an) + ntohs(h->ns);
    for (int i = 0; i < qd; i++) { p = skip_name(end, p); p += 4; }
    for (int i = 0; i < total; i++) {
        p = skip_name(end, p);
        if (p + 10 > end) return -1;
        uint16_t type = ntohs(*(const uint16_t *)p);
        uint16_t rdlen = ntohs(*(const uint16_t *)(p + 8));
        const uint8_t *rdata = p + 10;
        if (rdata + rdlen > end) return -1;
        if (type == 47) {                            /* NSEC: rdata starts w/ name */
            const uint8_t *rp = rdata;
            return read_name(base, end, &rp, next, nsz);
        }
        p = rdata + rdlen;
    }
    return -1;
}

/* print the first A record's address from a response, or "<none>" */
static void print_A(const uint8_t *dns, int dlen)
{
    const uint8_t *base = dns, *end = dns + dlen;
    const uint8_t *p = dns + sizeof(struct dnshdr);
    const struct dnshdr *h = (const struct dnshdr *)dns;
    int qd = ntohs(h->qd), an = ntohs(h->an);
    for (int i = 0; i < qd; i++) { p = skip_name(end, p); p += 4; }
    for (int i = 0; i < an; i++) {
        p = skip_name(end, p);
        if (p + 10 > end) break;
        uint16_t type = ntohs(*(const uint16_t *)p);
        uint16_t rdlen = ntohs(*(const uint16_t *)(p + 8));
        const uint8_t *rdata = p + 10;
        if (type == 1 && rdlen == 4) {
            struct in_addr a; memcpy(&a, rdata, 4);
            printf("%s", inet_ntoa(a)); return;
        }
        p = rdata + rdlen;
    }
    printf("<none>");
}

/* ---- MAC helpers ---- */
static int my_mac(const char *iface, uint8_t mac[6])
{
    char path[128], buf[32]; unsigned m[6];
    snprintf(path, sizeof path, "/sys/class/net/%s/address", iface);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return -1; }
    fclose(f);
    if (sscanf(buf, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
}

static int arp_mac(const char *ip, uint8_t mac[6])
{
    FILE *f = fopen("/proc/net/arp", "r"); if (!f) return -1;
    char line[256]; fgets(line, sizeof line, f);     /* header */
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char a[64], hw[64]; unsigned m[6];
        if (sscanf(line, "%63s %*s %*s %63s", a, hw) == 2 && strcmp(a, ip) == 0 &&
            sscanf(hw, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
            for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
            found = 0; break;
        }
    }
    fclose(f);
    return found;
}

int main(int argc, char **argv)
{
    const char *server = "172.16.3.30", *gw = "172.16.2.3", *src = "172.16.2.100";
    const char *zone = "example.com";
    int opt;
    while ((opt = getopt(argc, argv, "i:s:g:S:z:")) != -1) {
        switch (opt) {
        case 'i': snprintf(g_iface, sizeof g_iface, "%s", optarg); break;
        case 's': server = optarg; break;
        case 'g': gw = optarg; break;
        case 'S': src = optarg; break;
        case 'z': zone = optarg; break;
        default: fprintf(stderr, "usage: %s -i IF -s SERVER -g GATEWAY -S SRCIP -z ZONE\n", argv[0]);
                 return 2;
        }
    }
    g_server = inet_addr(server); g_src = inet_addr(src);
    srand((unsigned)time(NULL) ^ getpid());

    if (my_mac(g_iface, g_mymac) < 0) { fprintf(stderr, "no MAC on %s\n", g_iface); return 1; }
    for (int t = 0; t < 20 && arp_mac(gw, g_gwmac) < 0; t++) usleep(200000);
    if (arp_mac(gw, g_gwmac) < 0) { fprintf(stderr, "no ARP for gateway %s (ping it first)\n", gw); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(g_iface, 65535, 1, 50, errbuf);
    if (!g_pcap) { fprintf(stderr, "pcap: %s\n", errbuf); return 1; }
    char filter[256];
    snprintf(filter, sizeof filter, "udp and src host %s and src port 53 and dst host %s and udp dst port %u",
             server, src, g_sport);
    struct bpf_program bp;
    if (pcap_compile(g_pcap, &bp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &bp) < 0) {
        fprintf(stderr, "bpf: %s\n", pcap_geterr(g_pcap)); return 1;
    }

    fprintf(stderr, "[zonewalk] walking %s via NSEC at %s (libpcap capture+inject)\n", zone, server);

    char current[256], next[256], recovered[64][256];
    int nrec = 0;
    snprintf(current, sizeof current, "%s", zone);
    uint8_t resp[65536];

    for (int step = 0; step < 100; step++) {
        int n = query(current, 47, resp, sizeof resp);   /* NSEC */
        g_queries++;
        if (n < 0 || nsec_next(resp, n, next, sizeof next) < 0) {
            printf("  no NSEC returned for %s : chain not exposed (NSEC3 or not signed)\n", current);
            break;
        }
        printf("  NSEC %-22s -> %s\n", current, next);
        if (strcasecmp(current, zone) != 0 && nrec < 64)
            snprintf(recovered[nrec++], 256, "%s", current);
        if (strcasecmp(next, zone) == 0) break;           /* wrapped to apex */
        snprintf(current, sizeof current, "%s", next);
    }

    printf("\nNSEC queries sent : %ld\n", g_queries);
    printf("names recovered   : %d\n", nrec);
    for (int i = 0; i < nrec; i++) {
        int n = query(recovered[i], 1, resp, sizeof resp);  /* A, confirmation */
        printf("  %-24s ", recovered[i]);
        if (n > 0) print_A(resp, n); else printf("<no reply>");
        printf("\n");
    }
    pcap_close(g_pcap);
    return 0;
}
