#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "ft_ip.h"
#include "utils.h"


int create_ip_header(uint8_t *packet, const size_t packet_len,
                     const size_t data_len, const uint8_t tos, const uint8_t ttl,
                     const uint8_t protocol, const struct in_addr dest,
                     const uint8_t *opts, const size_t opts_len) {
    if (packet == NULL)
        return -1;
    if (opts_len > IP_MAX_OPTS_LEN || opts_len % 4 != 0)
        return -1;
    if (opts_len > 0 && opts == NULL)
        return -1;
 
    const size_t hdr_len = IP_MIN_HDR_LEN + opts_len;
    if (packet_len < hdr_len || hdr_len + data_len > UINT16_MAX)
        return -1;
 
    struct iphdr *ip = (struct iphdr *)packet;
 
    memset(ip, 0, IP_MIN_HDR_LEN);
    ip->version = 4;
    ip->ihl = hdr_len / 4;
    ip->tos = tos;
    ip->tot_len = htons((uint16_t)(hdr_len + data_len));
    ip->id = htons(getpid());
    ip->frag_off = 0;
    ip->ttl = ttl;
    ip->protocol = protocol;
    ip->saddr = 0; // 0 => kernel fills the right source address
    ip->daddr = dest.s_addr;
 
    if (opts_len > 0)
        memcpy(packet + IP_MIN_HDR_LEN, opts, opts_len);
 
    // checksum covers the header AND the options
    ip->check = 0;
    ip->check = checksum(packet, hdr_len);
    return (int)hdr_len;
}

size_t ip_build_rr_option(uint8_t *opt, const size_t opt_size) {
    if (opt == NULL || opt_size < IP_MAX_OPTS_LEN)
        return 0;
 
    memset(opt, 0, IP_MAX_OPTS_LEN);       // trailing 0 bytes = IPOPT_EOL padding
    opt[0] = IPOPT_RR;                     // type = 7
    opt[1] = 3 + 4 * IP_RR_MAX_ADDRS;      // option length = 39
    opt[2] = IPOPT_MINOFF;                 // pointer = 4 (first free slot)
    return IP_MAX_OPTS_LEN;                // 39 + 1 byte padding
}

int ip_parse(const uint8_t *packet, const size_t len, struct ip_info *info) {
    if (packet == NULL || info == NULL || len < IP_MIN_HDR_LEN)
        return IP_ERR_MALFORMED;
 
    const struct ip *ip = (const struct ip *)packet;
    const size_t hdr_len = (size_t)ip->ip_hl * 4;
    const size_t total_len = ntohs(ip->ip_len);
 
    if (ip->ip_v != 4 || hdr_len < IP_MIN_HDR_LEN || hdr_len > len ||
        total_len < hdr_len || total_len > len)
        return IP_ERR_MALFORMED;
 
    // A header with a correct checksum sums to 0 (checksum field included)
    if (checksum((void *)packet, hdr_len) != 0)
        return IP_ERR_CHECKSUM;
 
    info->version = ip->ip_v;
    info->hdr_len = (uint8_t)hdr_len;
    info->tos = ip->ip_tos;
    info->ttl = ip->ip_ttl;
    info->protocol = ip->ip_p;
    info->total_len = (uint16_t)total_len;
    info->id = ntohs(ip->ip_id);
    info->frag_off = ntohs(ip->ip_off);
    info->src = ip->ip_src;
    info->dst = ip->ip_dst;
    info->opts = hdr_len > IP_MIN_HDR_LEN ? packet + IP_MIN_HDR_LEN : NULL;
    info->opts_len = hdr_len - IP_MIN_HDR_LEN;
    info->payload = packet + hdr_len;
    info->payload_len = total_len - hdr_len;
    return 0;
}

size_t ip_get_rr_addrs(const struct ip_info *info, struct in_addr *addrs,
                       const size_t max) {
    if (info == NULL || addrs == NULL || info->opts == NULL)
        return 0;
 
    const uint8_t *opts = info->opts;
    size_t i = 0;
 
    while (i < info->opts_len) {
        if (opts[i] == IPOPT_EOL)
            break;
        if (opts[i] == IPOPT_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= info->opts_len)
            break;
 
        const size_t opt_len = opts[i + 1];
        if (opt_len < 2 || i + opt_len > info->opts_len)
            break;
 
        if (opts[i] == IPOPT_RR && opt_len >= 3) {
            // pointer is 1-based from option start: data begins at 4
            const size_t ptr = opts[i + 2];
            if (ptr < IPOPT_MINOFF) // RFC 791: smallest legal pointer is 4
                return 0;
            size_t end = ptr - 1 < opt_len ? ptr - 1 : opt_len; // bytes used
            size_t count = 0;
 
            for (size_t off = 3; off + 4 <= end && count < max; off += 4) {
                memcpy(&addrs[count].s_addr, opts + i + off, 4);
                count++;
            }
            return count;
        }
        i += opt_len;
    }
    return 0;
}
