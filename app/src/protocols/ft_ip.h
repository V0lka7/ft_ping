#ifndef FT_IP_H
#define FT_IP_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

// https://www.rfc-editor.org/info/rfc791

#define IP_MIN_HDR_LEN 20
#define IP_MAX_HDR_LEN 60
#define IP_MAX_OPTS_LEN 40 // IHL is 4 bits => 15 * 4 = 60 - 20
 
#define IP_RR_MAX_ADDRS 9 // 3 bytes of option header + 9 * 4 = 39 bytes
 
#define IP_ERR_MALFORMED -1
#define IP_ERR_CHECKSUM -2

struct ip_info {
    uint8_t version;
    uint8_t hdr_len; // in bytes (ihl * 4)
    uint8_t tos;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t total_len; // host byte order
    uint16_t id;        // host byte order
    uint16_t frag_off;  // host byte order (flags + offset)
    struct in_addr src;
    struct in_addr dst;
    const uint8_t *opts;
    size_t opts_len;
    const uint8_t *payload;
    size_t payload_len;
};

int create_ip_header(uint8_t *packet, const size_t packet_len,
                     const size_t data_len, const uint8_t tos, const uint8_t ttl,
                     const uint8_t protocol, const struct in_addr dest,
                     const uint8_t *opts, const size_t opts_len);

size_t ip_build_rr_option(uint8_t *opt, const size_t opt_size);

int ip_parse(const uint8_t *packet, const size_t len, struct ip_info *info);

size_t ip_get_rr_addrs(const struct ip_info *info, struct in_addr *addrs,
                       const size_t max);

#endif
